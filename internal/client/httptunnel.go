package client

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// HTTP tunnels are served by a small HTTP server inside the client rather
// than by copying bytes: each stream the server opens is one keep-alive
// connection carrying plain HTTP/1.1, so the client can see every request,
// add CORS headers, record requests for the inspector and replay them.

// Captured is one request as the client saw it.
type Captured struct {
	Time     time.Time
	Tunnel   int
	Local    string // local address the request was forwarded to
	Method   string
	Path     string // path and query
	Host     string // public host the visitor used
	Status   int
	Duration time.Duration
	Remote   string // visitor address, from the server's X-Forwarded-For
	Bytes    int64  // response body bytes
	Verified string // --verify result: "valid" or why it failed
	Mocked   bool   // answered by --mock, not the app
	Note     string // e.g. "simulated failure", "+800ms"

	ReqHeader     http.Header
	ReqBody       []byte
	ReqTruncated  bool
	RespHeader    http.Header
	RespBody      []byte
	RespTruncated bool
}

// streamListener hands tunnel streams to an http.Server as connections.
type streamListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newStreamListener() *streamListener {
	return &streamListener{ch: make(chan net.Conn, 64), done: make(chan struct{})}
}

func (l *streamListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *streamListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *streamListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero} }

func (l *streamListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		c.Close()
	}
}

// httpTunnel serves one HTTP tunnel's streams.
type httpTunnel struct {
	ln  *streamListener
	srv *http.Server
}

func newHTTPTunnel(idx int, t Tunnel, cfg Config) *httpTunnel {
	target := &url.URL{Scheme: "http", Host: t.Local}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host // apps see the public hostname, as they would behind any proxy
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
				if v := pr.In.Header.Get(h); v != "" {
					pr.Out.Header.Set(h, v)
				}
			}
			if cfg.Feedback && pr.In.Method == http.MethodGet && strings.Contains(pr.In.Header.Get("Accept"), "text/html") {
				pr.Out.Header.Del("Accept-Encoding") // the widget goes into plain HTML
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			cfg.Logger.Warn("cannot reach local service", "addr", t.Local, "err", err)
			w.Header().Set("PublicLocal-Error", "local-unavailable") // the server shows its own page for this
			http.Error(w, "publiclocal: local service unavailable", http.StatusBadGateway)
		},
	}
	if cfg.CORS || cfg.Feedback {
		proxy.ModifyResponse = func(resp *http.Response) error {
			if cfg.CORS {
				setCORS(resp.Header, resp.Request.Header.Get("Origin"))
			}
			if cfg.Feedback {
				return injectWidget(resp)
			}
			return nil
		}
	}
	h := &tunnelHandler{idx: idx, local: t.Local, proxy: proxy, cfg: cfg, live: &liveHub{}, feedback: &feedbackLimiter{}}
	ht := &httpTunnel{ln: newStreamListener()}
	ht.srv = &http.Server{Handler: h, ReadHeaderTimeout: 60 * time.Second}
	go ht.srv.Serve(ht.ln)
	return ht
}

func (ht *httpTunnel) close() {
	ht.ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ht.srv.Shutdown(ctx)
}

type tunnelHandler struct {
	idx   int
	local string
	proxy *httputil.ReverseProxy
	cfg   Config

	live     *liveHub
	feedback *feedbackLimiter
}

func (h *tunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remote := ""
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		remote = strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	switch {
	case h.cfg.Feedback && r.URL.Path == feedbackJS:
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		io.WriteString(w, widgetJS)
		return
	case h.cfg.Feedback && r.URL.Path == feedbackPath:
		h.serveFeedback(w, r, remote)
		return
	case h.cfg.LiveKey != "" && (r.URL.Path == livePath || r.URL.Path == liveEvents):
		h.serveLive(w, r)
		return
	}
	if h.cfg.CORS && r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		setCORS(w.Header(), r.Header.Get("Origin"))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	start := time.Now()
	c := Captured{Time: start, Tunnel: h.idx, Local: h.local, Method: r.Method, Path: r.URL.RequestURI(), Host: r.Host, Remote: remote}
	limit := h.cfg.CaptureBody
	if limit > 0 {
		c.ReqHeader = r.Header.Clone()
		if r.Body != nil && r.Body != http.NoBody {
			buf := &limitedBuffer{limit: limit}
			r.Body = &teeCloser{Reader: io.TeeReader(r.Body, buf), Closer: r.Body}
			defer func() { c.ReqBody, c.ReqTruncated = buf.Bytes(), buf.truncated }()
		}
	}
	cw := &captureWriter{ResponseWriter: w, status: http.StatusOK, buf: &limitedBuffer{limit: limit}}
	h.serve(cw, r, &c)
	c.Status, c.Bytes, c.Duration = cw.status, cw.bytes, time.Since(start)
	if limit > 0 {
		c.RespHeader = cw.Header().Clone()
		c.RespBody, c.RespTruncated = cw.buf.Bytes(), cw.buf.truncated
	}
	if h.cfg.OnRequest != nil {
		h.cfg.OnRequest(c)
	}
	if h.cfg.LiveKey != "" {
		note := c.Note
		if c.Verified != "" {
			note = strings.TrimSpace(note + " signature " + c.Verified)
		}
		if c.Mocked {
			note = strings.TrimSpace(note + " mock")
		}
		h.live.publish(LiveEvent{Time: start, Method: c.Method, Path: r.URL.Path, Status: c.Status, Millis: c.Duration.Milliseconds(), Note: note})
	}
}

// serve applies --verify, --latency, --fail and --mock, then hands the
// request to the app.
func (h *tunnelHandler) serve(w http.ResponseWriter, r *http.Request, c *Captured) {
	if v := h.cfg.Verify; v != nil {
		c.Verified = v.verifyRequest(r)
		if v.Strict && c.Verified != "" && c.Verified != "valid" {
			http.Error(w, "publiclocal: webhook signature check failed: "+c.Verified, http.StatusUnauthorized)
			return
		}
	}
	if ch := h.cfg.Chaos; ch.LatencyMax > 0 || ch.LatencyMin > 0 {
		d := ch.delay()
		c.Note = "+" + d.Round(time.Millisecond).String()
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			return
		}
	}
	if fr := h.cfg.Chaos.FailRate; fr > 0 && rand.Float64() < fr {
		c.Note = strings.TrimSpace(c.Note + " simulated failure")
		w.Header().Set("PublicLocal-Simulated", "fail")
		http.Error(w, "publiclocal: simulated failure (--fail)", http.StatusServiceUnavailable)
		return
	}
	for _, m := range h.cfg.Mocks {
		if m.matches(r) {
			c.Mocked = true
			m.serve(w)
			return
		}
	}
	h.proxy.ServeHTTP(w, r)
}

func setCORS(h http.Header, origin string) {
	if origin == "" {
		origin = "*"
	}
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD")
	h.Set("Access-Control-Allow-Headers", "*, Authorization, Content-Type")
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Max-Age", "600")
	if origin != "*" {
		h.Add("Vary", "Origin")
	}
}

// limitedBuffer keeps the first limit bytes written to it.
type limitedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
			b.truncated = true
		} else {
			b.Buffer.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

type teeCloser struct {
	io.Reader
	io.Closer
}

// captureWriter records status and body size, passing Flush and Hijack
// through so streaming and WebSockets keep working.
type captureWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
	buf    *limitedBuffer
}

func (c *captureWriter) WriteHeader(code int) { c.status = code; c.ResponseWriter.WriteHeader(code) }
func (c *captureWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.bytes += int64(n)
	if c.buf.limit > 0 {
		c.buf.Write(p[:n])
	}
	return n, err
}
func (c *captureWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }
func (c *captureWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (c *captureWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := c.ResponseWriter.(http.Hijacker); ok {
		c.status = http.StatusSwitchingProtocols
		return h.Hijack()
	}
	return nil, nil, errors.New("hijack not supported")
}
