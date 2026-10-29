// Package server is the public side of rtun: it accepts client sessions on a
// control port and forwards public HTTP and TCP traffic down those sessions.
package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/acme/autocert"

	"github.com/sevenoways/rtun/internal/pipe"
	"github.com/sevenoways/rtun/internal/proto"
)

type Config struct {
	// Domain is the base domain; HTTP tunnels are served at <sub>.<Domain>.
	Domain string

	ControlAddr string // client sessions, e.g. ":7000"
	HTTPAddr    string // plain HTTP, e.g. ":80"; empty disables
	HTTPSAddr   string // HTTPS with Let's Encrypt, e.g. ":443"; empty disables

	// Tokens clients must present. Empty means anyone may connect.
	Tokens []string

	// TCP tunnels get a port in [TCPPortMin, TCPPortMax], bound on TCPBindHost.
	TCPPortMin, TCPPortMax int
	TCPBindHost            string

	CertDir   string // autocert cache directory
	ACMEEmail string

	Logger *slog.Logger
}

type Server struct {
	cfg    Config
	log    *slog.Logger
	certs  *autocert.Manager
	scheme string // public scheme for HTTP tunnel URLs

	mu    sync.RWMutex
	hosts map[string]*httputil.ReverseProxy
}

func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.TCPPortMin == 0 && cfg.TCPPortMax == 0 {
		cfg.TCPPortMin, cfg.TCPPortMax = 10000, 20000
	}
	cfg.Domain = strings.ToLower(strings.TrimSuffix(cfg.Domain, "."))
	s := &Server{cfg: cfg, log: cfg.Logger, scheme: "http", hosts: map[string]*httputil.ReverseProxy{}}
	if cfg.HTTPSAddr != "" {
		s.scheme = "https"
		s.certs = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(cfg.CertDir),
			Email:      cfg.ACMEEmail,
			HostPolicy: s.hostPolicy,
		}
	}
	return s
}

// ListenAndServe runs every configured listener until ctx is cancelled or one fails.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if len(s.cfg.Tokens) == 0 {
		s.log.Warn("no tokens configured: anyone can open tunnels on this server")
	}
	errc := make(chan error, 3)
	var closers []io.Closer

	ctl, err := net.Listen("tcp", s.cfg.ControlAddr)
	if err != nil {
		return err
	}
	if s.certs != nil {
		// Clients reach the control port at the bare domain, so reuse its certificate.
		ctl = tls.NewListener(ctl, s.certs.TLSConfig())
	} else {
		s.log.Warn("HTTPS disabled: control connections and tokens are not encrypted")
	}
	closers = append(closers, ctl)
	go func() { errc <- s.ServeControl(ctl) }()
	s.log.Info("control listening", "addr", s.cfg.ControlAddr, "tls", s.certs != nil)

	if s.cfg.HTTPAddr != "" {
		var h http.Handler = s
		if s.certs != nil {
			h = s.certs.HTTPHandler(s) // answers ACME HTTP-01 challenges, passes the rest through
		}
		hs := &http.Server{Addr: s.cfg.HTTPAddr, Handler: h, ReadHeaderTimeout: 30 * time.Second}
		closers = append(closers, hs)
		go func() { errc <- hs.ListenAndServe() }()
		s.log.Info("http listening", "addr", s.cfg.HTTPAddr)
	}
	if s.cfg.HTTPSAddr != "" {
		hs := &http.Server{Addr: s.cfg.HTTPSAddr, Handler: s, TLSConfig: s.certs.TLSConfig(), ReadHeaderTimeout: 30 * time.Second}
		closers = append(closers, hs)
		go func() { errc <- hs.ListenAndServeTLS("", "") }()
		s.log.Info("https listening", "addr", s.cfg.HTTPSAddr)
	}

	select {
	case <-ctx.Done():
		err = nil
	case err = <-errc:
	}
	for _, c := range closers {
		c.Close()
	}
	return err
}

// ServeControl accepts client sessions on ln until it is closed.
func (s *Server) ServeControl(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleSession(conn)
	}
}

func (s *Server) hostPolicy(_ context.Context, host string) error {
	host = strings.ToLower(host)
	if host == s.cfg.Domain {
		return nil
	}
	if sub, ok := s.subdomain(host); ok {
		s.mu.RLock()
		_, active := s.hosts[sub]
		s.mu.RUnlock()
		if active {
			return nil
		}
	}
	return fmt.Errorf("rtun: no active tunnel for %q", host)
}

func (s *Server) subdomain(host string) (string, bool) {
	sub, ok := strings.CutSuffix(host, "."+s.cfg.Domain)
	if !ok || sub == "" || strings.Contains(sub, ".") {
		return "", false
	}
	return sub, true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	sub, ok := s.subdomain(host)
	if !ok {
		http.Error(w, "rtun: no tunnel here", http.StatusNotFound)
		return
	}
	s.mu.RLock()
	proxy := s.hosts[sub]
	s.mu.RUnlock()
	if proxy == nil {
		http.Error(w, "rtun: tunnel "+sub+" not found", http.StatusBadGateway)
		return
	}
	proxy.ServeHTTP(w, r)
}

var subdomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// session is one connected client and the tunnels it holds.
type session struct {
	srv       *Server
	ys        *yamux.Session
	log       *slog.Logger
	subs      []string
	listeners []net.Listener
}

func (s *Server) handleSession(conn net.Conn) {
	log := s.log.With("client", conn.RemoteAddr().String())
	ycfg := yamux.DefaultConfig()
	ycfg.LogOutput = io.Discard
	ys, err := yamux.Server(conn, ycfg)
	if err != nil {
		conn.Close()
		return
	}
	defer ys.Close()

	sess := &session{srv: s, ys: ys, log: log}
	defer sess.release()

	ctrl, err := acceptTimeout(ys, 10*time.Second)
	if err != nil {
		log.Debug("no control stream", "err", err)
		return
	}
	ctrl.SetDeadline(time.Now().Add(10 * time.Second))
	var hello proto.Hello
	if err := proto.Read(ctrl, &hello); err != nil {
		log.Debug("bad hello", "err", err)
		return
	}
	infos, err := sess.setup(hello)
	if err != nil {
		log.Info("session rejected", "err", err)
		proto.Write(ctrl, proto.HelloResp{Error: err.Error()})
		ctrl.Close()
		time.Sleep(100 * time.Millisecond) // let the error reach the client
		return
	}
	if err := proto.Write(ctrl, proto.HelloResp{Tunnels: infos}); err != nil {
		return
	}
	ctrl.SetDeadline(time.Time{})
	for _, t := range infos {
		log.Info("tunnel open", "url", t.URL)
	}

	go func() {
		io.Copy(io.Discard, ctrl) // the client closing its control stream ends the session
		ys.Close()
	}()
	<-ys.CloseChan()
	log.Info("session closed")
}

func acceptTimeout(ys *yamux.Session, d time.Duration) (net.Conn, error) {
	t := time.AfterFunc(d, func() { ys.Close() })
	defer t.Stop()
	return ys.Accept()
}

func (s *Server) checkToken(tok string) bool {
	if len(s.cfg.Tokens) == 0 {
		return true
	}
	ok := 0
	for _, t := range s.cfg.Tokens {
		ok |= subtle.ConstantTimeCompare([]byte(t), []byte(tok))
	}
	return ok == 1
}

func (sess *session) setup(h proto.Hello) ([]proto.TunnelInfo, error) {
	s := sess.srv
	if h.Version != proto.Version {
		return nil, fmt.Errorf("protocol version %d not supported (server speaks %d)", h.Version, proto.Version)
	}
	if !s.checkToken(h.Token) {
		return nil, errors.New("invalid token")
	}
	if len(h.Tunnels) == 0 || len(h.Tunnels) > 16 {
		return nil, errors.New("request between 1 and 16 tunnels")
	}
	infos := make([]proto.TunnelInfo, len(h.Tunnels))
	for i, t := range h.Tunnels {
		var err error
		switch t.Type {
		case proto.TypeHTTP:
			infos[i], err = sess.addHTTP(i, strings.ToLower(t.Subdomain))
		case proto.TypeTCP:
			infos[i], err = sess.addTCP(i, t.RemotePort)
		default:
			err = fmt.Errorf("unknown tunnel type %q", t.Type)
		}
		if err != nil {
			return nil, err
		}
	}
	return infos, nil
}

func (sess *session) addHTTP(idx int, sub string) (proto.TunnelInfo, error) {
	s := sess.srv
	if sub == "" {
		sub = randomName()
	} else if !subdomainRE.MatchString(sub) {
		return proto.TunnelInfo{}, fmt.Errorf("invalid subdomain %q", sub)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: "rtun-tunnel"})
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return sess.openStream(idx, "")
			},
			MaxIdleConnsPerHost: 32,
			IdleConnTimeout:     90 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			sess.log.Debug("proxy error", "err", err)
			http.Error(w, "rtun: local service unavailable", http.StatusBadGateway)
		},
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.hosts[sub]; taken {
		return proto.TunnelInfo{}, fmt.Errorf("subdomain %q is in use", sub)
	}
	s.hosts[sub] = proxy
	sess.subs = append(sess.subs, sub)
	return proto.TunnelInfo{Type: proto.TypeHTTP, URL: s.httpURL(sub)}, nil
}

func (s *Server) httpURL(sub string) string {
	addr, std := s.cfg.HTTPAddr, "80"
	if s.scheme == "https" {
		addr, std = s.cfg.HTTPSAddr, "443"
	}
	host := sub + "." + s.cfg.Domain
	if _, port, err := net.SplitHostPort(addr); err == nil && port != std && port != "" {
		host = net.JoinHostPort(host, port)
	}
	return s.scheme + "://" + host
}

func (sess *session) addTCP(idx, port int) (proto.TunnelInfo, error) {
	s := sess.srv
	var ln net.Listener
	var err error
	if port != 0 {
		if port < s.cfg.TCPPortMin || port > s.cfg.TCPPortMax {
			return proto.TunnelInfo{}, fmt.Errorf("port %d outside allowed range %d-%d", port, s.cfg.TCPPortMin, s.cfg.TCPPortMax)
		}
		ln, err = net.Listen("tcp", net.JoinHostPort(s.cfg.TCPBindHost, strconv.Itoa(port)))
	} else {
		ln, err = s.listenRandom()
	}
	if err != nil {
		return proto.TunnelInfo{}, fmt.Errorf("cannot open port: %w", err)
	}
	sess.listeners = append(sess.listeners, ln)
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	go sess.serveTCP(idx, ln)
	return proto.TunnelInfo{Type: proto.TypeTCP, URL: "tcp://" + net.JoinHostPort(s.cfg.Domain, p)}, nil
}

func (s *Server) listenRandom() (net.Listener, error) {
	span := int64(s.cfg.TCPPortMax - s.cfg.TCPPortMin + 1)
	var err error
	for range 50 {
		n, _ := rand.Int(rand.Reader, big.NewInt(span))
		port := s.cfg.TCPPortMin + int(n.Int64())
		var ln net.Listener
		if ln, err = net.Listen("tcp", net.JoinHostPort(s.cfg.TCPBindHost, strconv.Itoa(port))); err == nil {
			return ln, nil
		}
	}
	return nil, err
}

func (sess *session) serveTCP(idx int, ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			st, err := sess.openStream(idx, c.RemoteAddr().String())
			if err != nil {
				c.Close()
				return
			}
			pipe.Join(c, st)
		}()
	}
}

func (sess *session) openStream(idx int, remote string) (net.Conn, error) {
	st, err := sess.ys.Open()
	if err != nil {
		return nil, err
	}
	if err := proto.Write(st, proto.StreamHeader{Tunnel: idx, RemoteAddr: remote}); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

func (sess *session) release() {
	s := sess.srv
	s.mu.Lock()
	for _, sub := range sess.subs {
		if p := s.hosts[sub]; p != nil {
			p.Transport.(*http.Transport).CloseIdleConnections()
		}
		delete(s.hosts, sub)
	}
	s.mu.Unlock()
	for _, ln := range sess.listeners {
		ln.Close()
	}
}

func randomName() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}
