// Package server is the public side of publiclocal: it accepts client sessions on a
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
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"golang.org/x/crypto/acme/autocert"

	"github.com/sevenoways/publiclocal/internal/pipe"
	"github.com/sevenoways/publiclocal/internal/proto"
)

type Config struct {
	// Domain is the base domain; HTTP tunnels are served at <sub>.<Domain>.
	Domain string

	ControlAddr string // client sessions, e.g. ":7000"
	HTTPAddr    string // plain HTTP, e.g. ":80"; empty disables
	HTTPSAddr   string // HTTPS with Let's Encrypt, e.g. ":443"; empty disables
	AdminAddr   string // admin API, e.g. "127.0.0.1:7001"; empty disables

	// Tokens clients must present. Empty means anyone may connect.
	Tokens []string

	// TCP tunnels get a port in [TCPPortMin, TCPPortMax], bound on TCPBindHost.
	TCPPortMin, TCPPortMax int
	TCPBindHost            string

	CertDir   string // certificate cache directory
	ACMEEmail string

	// CloudflareToken switches HTTPS to one wildcard certificate obtained
	// through Cloudflare DNS, instead of one certificate per subdomain.
	CloudflareToken string

	// Public turns on the safeguards for a free, open instance: random
	// subdomains only, no TCP tunnels, the browser warning page, and default
	// values for the limits below.
	Public bool

	Warning      bool   // show a warning page to browsers before tunnel content
	AbuseContact string // mailto: or https: link shown on the warning page

	MaxTunnelAge       time.Duration // sessions are closed after this long; 0 = no limit
	MaxSessionsPerIP   int           // 0 = no limit
	RequestsPerMinute  int           // per HTTP tunnel; 0 = no limit
	MaxBytesPerSession int64         // traffic through one session; 0 = no limit
	MaxRequestBody     int64         // 0 = no limit

	BanFile string // banned client IPs, one per line; empty keeps bans in memory only

	Logger *slog.Logger
}

// Defaults used by Public mode for limits left at zero.
const (
	publicTunnelAge     = 2 * time.Hour
	publicSessionsPerIP = 3
	publicRequestsPerMi = 600
	publicBytesPerSess  = 2 << 30
	publicRequestBody   = 10 << 20
)

type Server struct {
	cfg    Config
	log    *slog.Logger
	certs  *autocert.Manager
	scheme string // public scheme for HTTP tunnel URLs

	mu       sync.RWMutex
	hosts    map[string]*route
	sessions map[*session]struct{}
	bans     map[string]bool
}

type route struct {
	sess    *session
	proxy   *httputil.ReverseProxy
	limiter *bucket
}

func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.TCPPortMin == 0 && cfg.TCPPortMax == 0 {
		cfg.TCPPortMin, cfg.TCPPortMax = 10000, 20000
	}
	if cfg.Public {
		cfg.Warning = true
		setDefault(&cfg.MaxTunnelAge, publicTunnelAge)
		setDefault(&cfg.MaxSessionsPerIP, publicSessionsPerIP)
		setDefault(&cfg.RequestsPerMinute, publicRequestsPerMi)
		setDefault(&cfg.MaxBytesPerSession, publicBytesPerSess)
		setDefault(&cfg.MaxRequestBody, publicRequestBody)
	}
	cfg.Domain = strings.ToLower(strings.TrimSuffix(cfg.Domain, "."))
	s := &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		scheme:   "http",
		hosts:    map[string]*route{},
		sessions: map[*session]struct{}{},
		bans:     loadBans(cfg.BanFile),
	}
	if cfg.HTTPSAddr != "" {
		s.scheme = "https"
		if cfg.CloudflareToken == "" {
			s.certs = &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				Cache:      autocert.DirCache(cfg.CertDir),
				Email:      cfg.ACMEEmail,
				HostPolicy: s.hostPolicy,
			}
		}
	}
	return s
}

func setDefault[T comparable](p *T, v T) {
	var zero T
	if *p == zero {
		*p = v
	}
}

// ListenAndServe runs every configured listener until ctx is cancelled or one fails.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if len(s.cfg.Tokens) == 0 && !s.cfg.Public {
		s.log.Warn("no tokens configured: anyone can open tunnels on this server")
	}
	var tlsCfg *tls.Config
	switch {
	case s.cfg.HTTPSAddr == "":
		s.log.Warn("HTTPS disabled: control connections and tokens are not encrypted")
	case s.certs != nil:
		tlsCfg = s.certs.TLSConfig()
	default:
		wc, err := newWildcard(s.cfg.Domain, s.cfg.CertDir, s.cfg.ACMEEmail, s.cfg.CloudflareToken, s.log)
		if err != nil {
			return fmt.Errorf("wildcard certificate: %w", err)
		}
		go wc.renewLoop(ctx)
		tlsCfg = &tls.Config{GetCertificate: wc.getCertificate}
	}

	errc := make(chan error, 4)
	var closers []io.Closer

	ctl, err := net.Listen("tcp", s.cfg.ControlAddr)
	if err != nil {
		return err
	}
	if tlsCfg != nil {
		// Clients reach the control port at the bare domain, so reuse its certificate.
		ctl = tls.NewListener(ctl, tlsCfg)
	}
	closers = append(closers, ctl)
	go func() { errc <- s.ServeControl(ctl) }()
	s.log.Info("control listening", "addr", s.cfg.ControlAddr, "tls", tlsCfg != nil, "public", s.cfg.Public)

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
	if tlsCfg != nil {
		hs := &http.Server{Addr: s.cfg.HTTPSAddr, Handler: s, TLSConfig: tlsCfg, ReadHeaderTimeout: 30 * time.Second}
		closers = append(closers, hs)
		go func() { errc <- hs.ListenAndServeTLS("", "") }()
		s.log.Info("https listening", "addr", s.cfg.HTTPSAddr)
	}
	if s.cfg.AdminAddr != "" {
		hs := &http.Server{Addr: s.cfg.AdminAddr, Handler: s.AdminHandler(), ReadHeaderTimeout: 30 * time.Second}
		closers = append(closers, hs)
		go func() { errc <- hs.ListenAndServe() }()
		s.log.Info("admin listening", "addr", s.cfg.AdminAddr)
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
	return fmt.Errorf("publiclocal: no active tunnel for %q", host)
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
		http.Error(w, "publiclocal: no tunnel here", http.StatusNotFound)
		return
	}
	s.mu.RLock()
	rt := s.hosts[sub]
	s.mu.RUnlock()
	if rt == nil {
		http.Error(w, "publiclocal: tunnel "+sub+" not found or expired", http.StatusBadGateway)
		return
	}
	if s.cfg.Public {
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	}
	if s.cfg.Warning {
		if r.URL.Path == continuePath {
			s.acceptWarning(w, r)
			return
		}
		if needsWarning(r) {
			s.serveWarning(w, r, host)
			return
		}
	}
	if rt.limiter != nil && !rt.limiter.allow() {
		http.Error(w, "publiclocal: too many requests to this tunnel", http.StatusTooManyRequests)
		return
	}
	if s.cfg.MaxRequestBody > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxRequestBody)
	}
	rt.proxy.ServeHTTP(w, r)
}

var subdomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// session is one connected client and the tunnels it holds.
type session struct {
	srv       *Server
	ys        *yamux.Session
	log       *slog.Logger
	ip        string
	created   time.Time
	subs      []string
	urls      []string
	listeners []net.Listener
	bytes     atomic.Int64
	overLimit atomic.Bool
}

func (s *Server) handleSession(conn net.Conn) {
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	log := s.log.With("client", conn.RemoteAddr().String())
	ycfg := yamux.DefaultConfig()
	ycfg.LogOutput = io.Discard
	ys, err := yamux.Server(conn, ycfg)
	if err != nil {
		conn.Close()
		return
	}
	defer ys.Close()

	sess := &session{srv: s, ys: ys, log: log, ip: ip, created: time.Now()}
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
		sess.release() // before replying, so a retry is not counted against the IP limit
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

	if age := s.cfg.MaxTunnelAge; age > 0 {
		t := time.AfterFunc(age, func() {
			log.Info("tunnel expired", "age", age)
			ys.Close()
		})
		defer t.Stop()
	}
	go func() {
		io.Copy(io.Discard, ctrl) // the client closing its control stream ends the session
		ys.Close()
	}()
	<-ys.CloseChan()
	log.Info("session closed", "bytes", sess.bytes.Load())
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
	if err := s.register(sess); err != nil {
		return nil, err
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
		sess.urls = append(sess.urls, infos[i].URL)
	}
	return infos, nil
}

// register checks bans and the per-IP session limit, and records the session.
func (s *Server) register(sess *session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bans[sess.ip] {
		return errors.New("this IP address is banned from this server")
	}
	if n := s.cfg.MaxSessionsPerIP; n > 0 {
		count := 0
		for other := range s.sessions {
			if other.ip == sess.ip {
				count++
			}
		}
		if count >= n {
			return fmt.Errorf("too many tunnels from your IP address (limit %d)", n)
		}
	}
	s.sessions[sess] = struct{}{}
	return nil
}

func (sess *session) addHTTP(idx int, sub string) (proto.TunnelInfo, error) {
	s := sess.srv
	switch {
	case sub == "":
		sub = randomName()
	case s.cfg.Public:
		return proto.TunnelInfo{}, errors.New("custom subdomains are not available on this public server; omit --subdomain to get a random one")
	case !subdomainRE.MatchString(sub):
		return proto.TunnelInfo{}, fmt.Errorf("invalid subdomain %q", sub)
	}
	rt := &route{sess: sess}
	if n := s.cfg.RequestsPerMinute; n > 0 {
		rt.limiter = newBucket(n)
	}
	rt.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "http", Host: "publiclocal-tunnel"})
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			stripWarningCookie(pr.Out)
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
			http.Error(w, "publiclocal: local service unavailable", http.StatusBadGateway)
		},
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, taken := s.hosts[sub]; taken {
		return proto.TunnelInfo{}, fmt.Errorf("subdomain %q is in use", sub)
	}
	s.hosts[sub] = rt
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
	if s.cfg.Public {
		return proto.TunnelInfo{}, errors.New("TCP tunnels are not available on this public server")
	}
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
	if sess.srv.cfg.MaxBytesPerSession > 0 {
		return &countingConn{Conn: st, sess: sess}, nil
	}
	return st, nil
}

// countingConn adds the bytes it carries to its session and closes the
// session once the traffic limit is exceeded.
type countingConn struct {
	net.Conn
	sess *session
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.sess.addBytes(n)
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.sess.addBytes(n)
	return n, err
}

func (sess *session) addBytes(n int) {
	if sess.bytes.Add(int64(n)) > sess.srv.cfg.MaxBytesPerSession && sess.overLimit.CompareAndSwap(false, true) {
		sess.log.Info("traffic limit reached, closing session", "limit", sess.srv.cfg.MaxBytesPerSession)
		go sess.ys.Close()
	}
}

func (sess *session) release() {
	s := sess.srv
	s.mu.Lock()
	for _, sub := range sess.subs {
		if rt := s.hosts[sub]; rt != nil {
			rt.proxy.Transport.(*http.Transport).CloseIdleConnections()
		}
		delete(s.hosts, sub)
	}
	delete(s.sessions, sess)
	s.mu.Unlock()
	for _, ln := range sess.listeners {
		ln.Close()
	}
}

func randomName() string {
	b := make([]byte, 5)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// bucket is a token-bucket rate limiter.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	rate   float64 // tokens per second
	last   time.Time
}

func newBucket(perMinute int) *bucket {
	return &bucket{tokens: float64(perMinute), max: float64(perMinute), rate: float64(perMinute) / 60, last: time.Now()}
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens = min(b.max, b.tokens+now.Sub(b.last).Seconds()*b.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
