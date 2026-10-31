package server

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/sevenoways/publiclocal/internal/proto"
)

// Anyone with an SSH client can open a tunnel without installing anything:
//
//	ssh -p 443 -R0:localhost:3000 publiclocal.app
//
// Each remote forward (-R) becomes an HTTP link. The link and a live request
// feed are printed in the SSH window. Links made this way are anonymous and
// end with the connection; the publiclocal client adds passwords, the
// inspector and links that survive restarts.

const (
	maxSSHForwards    = 16               // remote forwards per connection, as for the client's Hello
	maxPendingLines   = 100              // text kept for an SSH window that has not opened yet
	sshOutQueue       = 256              // lines waiting to be written to a slow SSH window
	sshOpenTimeout    = 15 * time.Second // for the client to accept a forwarded channel
	sshHandshakeLimit = 20 * time.Second
	muxPeekTimeout    = 10 * time.Second
	maxMuxPeeking     = 2048 // connections on the shared port still being classified
)

// SSHHostKey loads the server's SSH host key, creating it on first start.
// An unreadable existing key is an error: replacing it silently would make
// every client warn that the server's identity changed.
func SSHHostKey(path string, log func(msg string, args ...any)) (ssh.Signer, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if runtime.GOOS != "windows" {
			if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
				log("ssh host key file is readable by other users; chmod 600 it", "path", path)
			}
		}
		return ssh.ParsePrivateKey(b)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "publiclocal host key")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

func (s *Server) sshConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{ServerVersion: "SSH-2.0-PublicLocal", MaxAuthTries: 3}
	cfg.AddHostKey(s.sshKey)
	if len(s.cfg.Tokens) == 0 {
		cfg.NoClientAuth = true
		return cfg
	}
	// Private servers: the token is the user name or the password.
	cfg.NoClientAuth = true
	cfg.NoClientAuthCallback = func(c ssh.ConnMetadata) (*ssh.Permissions, error) {
		if s.checkToken(c.User()) {
			return nil, nil
		}
		return nil, errors.New("token required")
	}
	cfg.PasswordCallback = func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
		if s.checkToken(string(pw)) || s.checkToken(c.User()) {
			return nil, nil
		}
		return nil, errors.New("invalid token")
	}
	return cfg
}

// ServeSSH accepts SSH tunnel clients on ln until it is closed.
func (s *Server) ServeSSH(ln net.Listener) error {
	var backoff time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			backoff = acceptBackoff(backoff)
			s.log.Warn("ssh accept failed, retrying", "err", err, "in", backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		if !s.connLimit.allow(ipKey(c.RemoteAddr().String())) {
			c.Close()
			continue
		}
		go s.handleSSH(c)
	}
}

// acceptBackoff mirrors net/http: running out of file descriptors must slow
// accepting down, never stop the server.
func acceptBackoff(d time.Duration) time.Duration {
	if d == 0 {
		return 5 * time.Millisecond
	}
	return min(d*2, time.Second)
}

type sshForward struct {
	addr string
	port uint32
}

// sshTransport opens a forwarded-tcpip channel per stream, which the SSH
// client connects to the target of its -R option.
type sshTransport struct {
	conn   *ssh.ServerConn
	mu     sync.Mutex
	fwd    []sshForward
	closed chan struct{}
	once   sync.Once
}

func (t *sshTransport) open(idx int, remote string) (net.Conn, error) {
	t.mu.Lock()
	if idx >= len(t.fwd) {
		t.mu.Unlock()
		return nil, errors.New("no such forward")
	}
	f := t.fwd[idx]
	t.mu.Unlock()
	host, portStr, _ := net.SplitHostPort(remote)
	port, _ := strconv.Atoi(portStr)
	if host == "" || port == 0 {
		// HTTP streams are pooled, so there is no single visitor to name; some
		// clients reject port 0, so give a stand-in origin.
		host, port = "127.0.0.1", 443
	}
	payload := ssh.Marshal(struct {
		Addr       string
		Port       uint32
		OriginAddr string
		OriginPort uint32
	}{f.addr, f.port, host, uint32(port)})

	// A client that never answers must not hold visitors' requests forever.
	type result struct {
		ch   ssh.Channel
		reqs <-chan *ssh.Request
		err  error
	}
	done := make(chan result, 1)
	go func() {
		ch, reqs, err := t.conn.OpenChannel("forwarded-tcpip", payload)
		done <- result{ch, reqs, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return nil, r.err
		}
		go ssh.DiscardRequests(r.reqs)
		return &chanConn{Channel: r.ch, local: t.conn.LocalAddr(), remote: t.conn.RemoteAddr()}, nil
	case <-time.After(sshOpenTimeout):
		go func() {
			if r := <-done; r.err == nil {
				r.ch.Close()
			}
		}()
		return nil, errors.New("ssh client did not accept the connection in time")
	case <-t.closed:
		return nil, net.ErrClosed
	}
}

func (t *sshTransport) close() error {
	t.once.Do(func() { close(t.closed) })
	return t.conn.Close()
}

func (t *sshTransport) done() <-chan struct{} { return t.closed }

// chanConn adapts an SSH channel to net.Conn for the HTTP transport.
type chanConn struct {
	ssh.Channel
	local, remote net.Addr
}

func (c *chanConn) LocalAddr() net.Addr              { return c.local }
func (c *chanConn) RemoteAddr() net.Addr             { return c.remote }
func (c *chanConn) SetDeadline(time.Time) error      { return nil }
func (c *chanConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chanConn) SetWriteDeadline(time.Time) error { return nil }

// sshOut writes text to the SSH window. Lines wait (up to a limit) until the
// client opens a window, and are written by one goroutine through a bounded
// queue, so a client that stops reading only loses lines and never stalls
// the connection.
type sshOut struct {
	mu      sync.Mutex
	open    bool
	pending []string
	queue   chan string
	stop    chan struct{}
}

func newSSHOut(stop chan struct{}) *sshOut {
	return &sshOut{queue: make(chan string, sshOutQueue), stop: stop}
}

func (o *sshOut) say(lines ...string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, l := range lines {
		l = strings.ReplaceAll(l, "\n", "\r\n") + "\r\n"
		if !o.open {
			if len(o.pending) >= maxPendingLines {
				o.pending = o.pending[1:]
			}
			o.pending = append(o.pending, l)
			continue
		}
		select {
		case o.queue <- l:
		default: // the window is not draining; drop the line
		}
	}
}

// attach starts writing to ch. Only the first window is used.
func (o *sshOut) attach(ch ssh.Channel) bool {
	o.mu.Lock()
	if o.open {
		o.mu.Unlock()
		return false
	}
	o.open = true
	pending := o.pending
	o.pending = nil
	o.mu.Unlock()
	go func() {
		for _, l := range pending {
			if _, err := ch.Write([]byte(l)); err != nil {
				return
			}
		}
		for {
			select {
			case l := <-o.queue:
				if _, err := ch.Write([]byte(l)); err != nil {
					return
				}
			case <-o.stop:
				return
			}
		}
	}()
	return true
}

// printable replaces control and formatting characters (including C1
// controls and bidi overrides) so visitor-supplied text cannot drive or
// spoof the SSH terminal, and limits the length to n runes.
func printable(s string, n int) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count == n {
			b.WriteString("…")
			break
		}
		if !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) {
			r = '?'
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}

func (s *Server) handleSSH(c net.Conn) {
	ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	log := s.log.With("client", c.RemoteAddr().String(), "via", "ssh")
	c.SetDeadline(time.Now().Add(sshHandshakeLimit))
	conn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig())
	if err != nil {
		c.Close()
		log.Debug("ssh handshake failed", "err", err)
		return
	}
	c.SetDeadline(time.Time{})
	tr := &sshTransport{conn: conn, closed: make(chan struct{})}
	defer tr.close()
	go func() { conn.Wait(); tr.close() }()

	sess := &session{srv: s, tr: tr, log: log, ip: ip, ipKey: ipKey(ip), created: time.Now(), events: make(chan proto.Event, 256)}
	out := newSSHOut(tr.closed)
	out.say("", "  PublicLocal  ·  "+s.baseURL(), "")
	if err := s.register(sess); err != nil {
		out.say("  Sorry: "+err.Error(), "")
		s.sshFarewell(conn, chans, reqs, out)
		return
	}
	defer s.retireSSH(sess)
	defer sess.release()
	log.Info("ssh session open")
	if u := conn.User(); strings.Contains(u, "=") && len(s.cfg.Tokens) == 0 {
		if summary, err := s.applySSHOptions(sess, strings.Split(u, "+")); err != nil {
			out.say("  Options not applied: "+err.Error(), "")
		} else if summary != "" {
			out.say("  Options: "+summary, "")
		}
	}

	go s.sshKeepalive(conn, tr)
	go s.sshFeed(sess, out)
	go s.sshChannels(chans, out, tr, sess)

	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			s.sshForward(req, sess, tr, out)
		default:
			// cancel-tcpip-forward is refused rather than pretending: links
			// end when the connection does.
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
	log.Info("ssh session closed", "bytes", sess.bytes.Load())
}

// sshOptSet holds options an SSH user gave, for links made later in the session.
type sshOptSet struct {
	req     proto.TunnelReq
	expires time.Duration
}

// applySSHOptions parses `name=value` words and applies them to the
// session's links, now and later. It returns a summary for the SSH window.
func (s *Server) applySSHOptions(sess *session, words []string) (string, error) {
	t, expires, err := sshOptions(words)
	if err != nil {
		return "", err
	}
	opts, err := s.parseLinkOpts(t)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	sess.sshOpts = &sshOptSet{req: t, expires: expires}
	for _, sub := range sess.subs {
		if rt := s.hosts[sub]; rt != nil && rt.sess == sess {
			rt.opts.Store(opts)
		}
		s.shortenLocked(sub, expires)
	}
	s.saveLocked()
	s.mu.Unlock()
	var parts []string
	if opts.password != "" {
		parts = append(parts, "password set")
	}
	if expires > 0 {
		parts = append(parts, "expires in "+expires.String())
	}
	if opts.maxVisit > 0 {
		parts = append(parts, fmt.Sprintf("first %d visitor(s) only", opts.maxVisit))
	}
	if opts.hostHeader != "" {
		parts = append(parts, "Host header "+opts.hostHeader)
	}
	if len(opts.allowNets) > 0 {
		parts = append(parts, fmt.Sprintf("%d allowed network(s)", len(opts.allowNets)))
	}
	if opts.needsGitHub {
		parts = append(parts, "GitHub sign-in required")
	}
	if opts.note != "" {
		parts = append(parts, "note shown to visitors")
	}
	return strings.Join(parts, ", "), nil
}

// shortenLocked brings a link's expiry forward, never later. Callers hold s.mu.
func (s *Server) shortenLocked(sub string, d time.Duration) {
	if d <= 0 {
		return
	}
	res := s.reservations[sub]
	if res == nil {
		return
	}
	if want := time.Now().Add(d); res.Expires.IsZero() || want.Before(res.Expires) {
		res.Expires = want
		s.scheduleExpiry(res)
	}
}

// sshForward turns one `-R` request into a link.
func (s *Server) sshForward(req *ssh.Request, sess *session, tr *sshTransport, out *sshOut) {
	var r struct {
		Addr string
		Port uint32
	}
	if ssh.Unmarshal(req.Payload, &r) != nil {
		req.Reply(false, nil)
		return
	}
	tr.mu.Lock()
	idx := len(tr.fwd)
	tr.mu.Unlock()
	if idx >= maxSSHForwards {
		out.say(fmt.Sprintf("  At most %d links per connection.", maxSSHForwards))
		req.Reply(false, nil)
		return
	}
	port := r.Port
	if port == 0 {
		port = 80
	}
	want := ""
	if a := strings.ToLower(r.Addr); !s.cfg.Public && a != "" && a != "localhost" && a != "0.0.0.0" && a != "127.0.0.1" && a != "*" && a != "::" {
		want = a // `ssh -R myapp:80:localhost:3000` asks for a name on private servers
	}
	// Register the forward before the link exists, so a visitor arriving at
	// once finds it; take it back if the link is refused.
	tr.mu.Lock()
	tr.fwd = append(tr.fwd, sshForward{addr: r.Addr, port: port})
	tr.mu.Unlock()
	treq := proto.TunnelReq{Type: proto.TypeHTTP, Subdomain: want}
	var expires time.Duration
	s.mu.RLock()
	if o := sess.sshOpts; o != nil {
		saved := o.req
		saved.Type, saved.Subdomain = proto.TypeHTTP, want
		treq, expires = saved, o.expires
	}
	s.mu.RUnlock()
	info, err := sess.addHTTP(idx, treq)
	if err != nil {
		tr.mu.Lock()
		tr.fwd = tr.fwd[:idx]
		tr.mu.Unlock()
		out.say("  Could not open a link: " + err.Error())
		req.Reply(false, nil)
		return
	}
	s.mu.Lock()
	sess.urls = append(sess.urls, info.URL)
	s.shortenLocked(info.Name, expires)
	if res := s.reservations[info.Name]; res != nil {
		info.Expires = res.Expires
	}
	s.mu.Unlock()
	var reply []byte
	if r.Port == 0 {
		reply = ssh.Marshal(struct{ Port uint32 }{port})
	}
	req.Reply(true, reply)
	sess.log.Info("tunnel open", "url", info.URL, "expires", info.Expires)
	lines := []string{"  Forwarding  " + info.URL}
	if !info.Expires.IsZero() {
		lines = append(lines, "  Link valid until "+info.Expires.UTC().Format("Mon 2 Jan 15:04")+" UTC, or until you disconnect")
	}
	lines = append(lines, "",
		"  Requests appear below. Press Ctrl+C to stop.",
		"  For passwords, the inspector and links that survive restarts:",
		"  "+s.baseURL()+"/#install",
		"")
	out.say(lines...)
}

// sshChannels serves one session channel (where text is shown) and refuses
// everything else, including further session channels.
func (s *Server) sshChannels(chans <-chan ssh.NewChannel, out *sshOut, tr *sshTransport, sess *session) {
	var opened atomic.Bool
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.Prohibited, "only remote forwarding (-R) is supported")
			continue
		}
		if !opened.CompareAndSwap(false, true) {
			nc.Reject(ssh.ResourceShortage, "one session per connection")
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go func() {
			for r := range reqs {
				if r.Type == "exec" {
					var cmd struct{ Command string }
					if ssh.Unmarshal(r.Payload, &cmd) == nil && len(cmd.Command) <= 2048 {
						if words := strings.Fields(cmd.Command); len(words) > 0 {
							if summary, err := s.applySSHOptions(sess, words); err != nil {
								out.say("  Options not applied: "+printable(err.Error(), 200), "")
							} else if summary != "" {
								out.say("  Options: "+summary, "")
							}
						}
					}
				}
				switch r.Type {
				case "pty-req", "shell", "exec", "env", "window-change":
					if r.WantReply {
						r.Reply(true, nil)
					}
				default:
					if r.WantReply {
						r.Reply(false, nil)
					}
				}
			}
		}()
		out.attach(ch)
		go func() {
			// Ctrl+C or Ctrl+D in the SSH window ends the tunnel.
			buf := make([]byte, 64)
			for {
				n, err := ch.Read(buf)
				if err != nil {
					return
				}
				for _, b := range buf[:n] {
					if b == 3 || b == 4 {
						ch.Write([]byte("\r\n  Tunnel closed.\r\n\r\n"))
						ch.Close()
						tr.close()
						return
					}
				}
			}
		}()
	}
}

// sshFeed prints each request served by the session's links.
func (s *Server) sshFeed(sess *session, out *sshOut) {
	for {
		select {
		case ev := <-sess.events:
			out.say(fmt.Sprintf("  %s  %-6s %-40s %d  %4d ms  %s", time.Now().UTC().Format("15:04:05"),
				printable(ev.Method, 8), printable(ev.Path, 40), ev.Status, ev.Millis, printable(ev.Remote, 45)))
		case <-sess.tr.done():
			return
		}
	}
}

// sshKeepalive notices clients that vanished without closing the connection.
func (s *Server) sshKeepalive(conn *ssh.ServerConn, tr *sshTransport) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-tr.done():
			return
		case <-t.C:
			ok := make(chan struct{})
			go func() {
				conn.SendRequest("keepalive@openssh.com", true, nil)
				close(ok)
			}()
			select {
			case <-ok:
			case <-time.After(60 * time.Second):
				tr.close()
				return
			}
		}
	}
}

// sshFarewell shows a refusal message in the SSH window before closing.
func (s *Server) sshFarewell(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, out *sshOut) {
	go func() {
		for r := range reqs {
			if r.WantReply {
				r.Reply(false, nil)
			}
		}
	}()
	timer := time.AfterFunc(5*time.Second, func() { conn.Close() })
	defer timer.Stop()
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.Prohibited, "refused")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(creqs)
		out.attach(ch)
		time.Sleep(200 * time.Millisecond)
		ch.Close()
		conn.Close()
		return
	}
}

// retireSSH ends an SSH session's links: they cannot be reclaimed, so they
// should not hold a place against the per-network link limit. A summary is
// kept for their "expired" page.
func (s *Server) retireSSH(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sub := range sess.newSubs {
		res := s.reservations[sub]
		if res == nil {
			continue
		}
		if res.timer != nil {
			res.timer.Stop()
		}
		if res.LastOnline.IsZero() {
			res.LastOnline = time.Now()
		}
		res.Expires = res.LastOnline
		res.seen = nil
		s.history[sub] = res
		delete(s.reservations, sub)
	}
	s.saveLocked()
}

// sshMux lets SSH share a port with HTTPS: SSH clients send "SSH-" first,
// TLS clients a handshake record, so the first byte decides. Connections
// that are not SSH are handed on as a net.Listener for the HTTPS server.
type sshMux struct {
	net.Listener
	srv     *Server
	conns   chan net.Conn
	errc    chan error
	peeking chan struct{} // bounds connections still being classified
}

func (s *Server) newSSHMux(ln net.Listener) *sshMux {
	m := &sshMux{Listener: ln, srv: s, conns: make(chan net.Conn), errc: make(chan error, 1), peeking: make(chan struct{}, maxMuxPeeking)}
	go m.loop()
	return m
}

// SSHMuxForTest wraps ln like --ssh-on-https does; non-SSH connections come
// out of the returned listener.
func (s *Server) SSHMuxForTest(ln net.Listener) net.Listener { return s.newSSHMux(ln) }

func (m *sshMux) loop() {
	var backoff time.Duration
	for {
		c, err := m.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				m.errc <- err
				return
			}
			// Out of file descriptors or similar: slow down, never stop serving.
			backoff = acceptBackoff(backoff)
			m.srv.log.Warn("accept failed, retrying", "err", err, "in", backoff)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		select {
		case m.peeking <- struct{}{}:
		default:
			c.Close() // too many connections that have not said anything yet
			continue
		}
		go m.classify(c)
	}
}

func (m *sshMux) classify(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(muxPeekTimeout))
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	c.SetReadDeadline(time.Time{})
	<-m.peeking
	if err != nil {
		c.Close()
		return
	}
	pc := &peekedConn{Conn: c, r: br}
	if b[0] == 'S' {
		if !m.srv.connLimit.allow(ipKey(c.RemoteAddr().String())) {
			c.Close()
			return
		}
		m.srv.handleSSH(pc)
		return
	}
	select {
	case m.conns <- pc:
	case <-time.After(muxPeekTimeout):
		c.Close() // the HTTPS server is not accepting; don't pile up
	}
}

func (m *sshMux) Accept() (net.Conn, error) {
	select {
	case c := <-m.conns:
		return c, nil
	case err := <-m.errc:
		m.errc <- err
		return nil, err
	}
}

type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.r.Read(b) }
