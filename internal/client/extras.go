package client

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Paths the client answers itself on every HTTP link. The server's gates
// (warning page, password, IP and GitHub limits) apply to them as to the app.
const (
	feedbackJS   = "/.publiclocal/feedback.js"
	feedbackPath = "/.publiclocal/feedback"
	livePath     = "/.publiclocal/live"
	liveEvents   = "/.publiclocal/live/events"
)

// ---------------------------------------------------------------------------
// Webhook signature checks (--verify)

// Verifier checks webhook signatures from one provider.
type Verifier struct {
	Provider string // stripe, github, slack or shopify
	Secret   string
	Strict   bool // refuse requests that fail, with 401, before they reach the app
}

// Providers that --verify understands.
var verifyProviders = []string{"stripe", "github", "slack", "shopify"}

// ParseVerifier reads "provider:secret".
func ParseVerifier(spec string) (*Verifier, error) {
	p, secret, ok := strings.Cut(spec, ":")
	p = strings.ToLower(strings.TrimSpace(p))
	if !ok || secret == "" {
		return nil, fmt.Errorf("--verify wants provider:secret, e.g. stripe:whsec_...")
	}
	for _, known := range verifyProviders {
		if p == known {
			return &Verifier{Provider: p, Secret: secret}, nil
		}
	}
	return nil, fmt.Errorf("--verify: unknown provider %q (use %s)", p, strings.Join(verifyProviders, ", "))
}

// maxVerifyBody is the largest body checked; larger ones are reported, not hashed.
const maxVerifyBody = 1 << 20

// signatureTolerance is how old a signed timestamp may be (Stripe, Slack).
const signatureTolerance = 5 * time.Minute

// Check returns "valid" or the reason the request failed.
func (v *Verifier) Check(h http.Header, body []byte, now time.Time) string {
	mac := func(msg []byte) []byte {
		m := hmac.New(sha256.New, []byte(v.Secret))
		m.Write(msg)
		return m.Sum(nil)
	}
	fresh := func(ts string) bool {
		n, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			return false
		}
		d := now.Sub(time.Unix(n, 0))
		return d < signatureTolerance && d > -signatureTolerance
	}
	switch v.Provider {
	case "stripe":
		sh := h.Get("Stripe-Signature")
		if sh == "" {
			return "no Stripe-Signature header"
		}
		var ts string
		var sigs [][]byte
		for part := range strings.SplitSeq(sh, ",") {
			k, val, _ := strings.Cut(strings.TrimSpace(part), "=")
			switch k {
			case "t":
				ts = val
			case "v1":
				if b, err := hex.DecodeString(val); err == nil {
					sigs = append(sigs, b)
				}
			}
		}
		if ts == "" || len(sigs) == 0 {
			return "malformed Stripe-Signature"
		}
		want := mac(append([]byte(ts+"."), body...))
		for _, s := range sigs {
			if hmac.Equal(s, want) {
				if !fresh(ts) {
					return "signature too old (replayed?)"
				}
				return "valid"
			}
		}
		return "bad signature (wrong secret, or body changed)"
	case "github":
		sh := h.Get("X-Hub-Signature-256")
		if sh == "" {
			return "no X-Hub-Signature-256 header"
		}
		got, err := hex.DecodeString(strings.TrimPrefix(sh, "sha256="))
		if err != nil || !strings.HasPrefix(sh, "sha256=") {
			return "malformed X-Hub-Signature-256"
		}
		if !hmac.Equal(got, mac(body)) {
			return "bad signature (wrong secret, or body changed)"
		}
		return "valid"
	case "slack":
		sh, ts := h.Get("X-Slack-Signature"), h.Get("X-Slack-Request-Timestamp")
		if sh == "" || ts == "" {
			return "no X-Slack-Signature or timestamp header"
		}
		got, err := hex.DecodeString(strings.TrimPrefix(sh, "v0="))
		if err != nil || !strings.HasPrefix(sh, "v0=") {
			return "malformed X-Slack-Signature"
		}
		if !hmac.Equal(got, mac(append([]byte("v0:"+ts+":"), body...))) {
			return "bad signature (wrong secret, or body changed)"
		}
		if !fresh(ts) {
			return "signature too old (replayed?)"
		}
		return "valid"
	case "shopify":
		sh := h.Get("X-Shopify-Hmac-Sha256")
		if sh == "" {
			return "no X-Shopify-Hmac-Sha256 header"
		}
		got, err := base64.StdEncoding.DecodeString(sh)
		if err != nil {
			return "malformed X-Shopify-Hmac-Sha256"
		}
		if !hmac.Equal(got, mac(body)) {
			return "bad signature (wrong secret, or body changed)"
		}
		return "valid"
	}
	return "unknown provider"
}

// verifyRequest reads the body (up to maxVerifyBody) so it can be hashed,
// then puts it back for the app.
func (v *Verifier) verifyRequest(r *http.Request) string {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return "" // pages and assets are not webhooks: not checked, not refused
	}
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxVerifyBody+1))
		if err != nil {
			return "could not read body"
		}
		r.Body = &teeCloser{Reader: io.MultiReader(bytes.NewReader(b), r.Body), Closer: r.Body}
		if len(b) > maxVerifyBody {
			return "body too large to check"
		}
		body = b
	}
	return v.Check(r.Header, body, time.Now())
}

// ---------------------------------------------------------------------------
// Mock responses (--mock)

// Mock answers matching requests itself instead of the app.
type Mock struct {
	Method string // empty for any
	Path   string // exact, or a prefix when Prefix is set
	Prefix bool
	Status int
	File   string // body comes from this file, read on every request
}

// ParseMock reads "[METHOD ]PATH=TARGET", where TARGET is a file, a status
// code, or "STATUS:file". A PATH ending in * matches everything under it.
func ParseMock(spec string) (Mock, error) {
	lhs, target, ok := strings.Cut(spec, "=")
	lhs, target = strings.TrimSpace(lhs), strings.TrimSpace(target)
	if !ok || lhs == "" || target == "" {
		return Mock{}, fmt.Errorf("--mock wants PATH=FILE, PATH=STATUS or PATH=STATUS:FILE, e.g. /api/users=users.json")
	}
	var m Mock
	if method, path, ok := strings.Cut(lhs, " "); ok {
		m.Method, lhs = strings.ToUpper(method), strings.TrimSpace(path)
	}
	if !strings.HasPrefix(lhs, "/") {
		return Mock{}, fmt.Errorf("--mock: path %q must start with /", lhs)
	}
	if strings.HasSuffix(lhs, "*") {
		m.Prefix, lhs = true, strings.TrimSuffix(lhs, "*")
	}
	m.Path, m.Status = lhs, http.StatusOK
	code, file, hasFile := strings.Cut(target, ":")
	if n, err := strconv.Atoi(code); err == nil && n >= 100 && n <= 599 && (hasFile || len(code) == 3) {
		m.Status = n
		if hasFile {
			m.File = file
		}
	} else {
		m.File = target
	}
	if m.File != "" && (m.Status < 200 || m.Status == http.StatusNoContent || m.Status == http.StatusNotModified) {
		return Mock{}, fmt.Errorf("--mock: status %d cannot have a body", m.Status)
	}
	if m.File != "" {
		if _, err := os.Stat(m.File); err != nil {
			return Mock{}, fmt.Errorf("--mock: %v", err)
		}
	}
	return m, nil
}

func (m Mock) matches(r *http.Request) bool {
	if m.Method != "" && m.Method != r.Method {
		return false
	}
	p := path.Clean("/" + r.URL.Path)
	if m.Prefix {
		return strings.HasPrefix(p+"/", m.Path) || strings.HasPrefix(p, m.Path)
	}
	return p == path.Clean(m.Path)
}

// maxMockFile bounds what a mock serves.
const maxMockFile = 10 << 20

func (m Mock) serve(w http.ResponseWriter) {
	w.Header().Set("PublicLocal-Mock", "1")
	if m.File == "" {
		w.WriteHeader(m.Status)
		return
	}
	f, err := os.Open(m.File)
	if err != nil {
		http.Error(w, "publiclocal: mock file missing: "+filepath.Base(m.File), http.StatusInternalServerError)
		return
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxMockFile))
	if err != nil {
		http.Error(w, "publiclocal: cannot read mock file", http.StatusInternalServerError)
		return
	}
	ct := mime.TypeByExtension(filepath.Ext(m.File))
	if ct == "" {
		ct = http.DetectContentType(b)
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(m.Status)
	w.Write(b)
}

// ---------------------------------------------------------------------------
// Bad-network simulation (--latency, --fail)

// Chaos slows or fails requests on purpose, to test how an app copes.
type Chaos struct {
	LatencyMin, LatencyMax time.Duration // each request waits a random time in this range
	FailRate               float64       // share of requests answered 503, 0..1
}

// ParseLatency reads "800ms" or "200ms-1s".
func ParseLatency(s string) (lo, hi time.Duration, err error) {
	a, b, isRange := strings.Cut(s, "-")
	if lo, err = time.ParseDuration(strings.TrimSpace(a)); err != nil {
		return 0, 0, fmt.Errorf("--latency: %v", err)
	}
	hi = lo
	if isRange {
		if hi, err = time.ParseDuration(strings.TrimSpace(b)); err != nil {
			return 0, 0, fmt.Errorf("--latency: %v", err)
		}
	}
	if lo < 0 || hi < lo || hi > time.Minute {
		return 0, 0, errors.New("--latency: use a delay up to 1m, or a range like 200ms-1s")
	}
	return lo, hi, nil
}

// ParseFailRate reads "10%" or "0.1".
func ParseFailRate(s string) (float64, error) {
	s = strings.TrimSpace(s)
	pct := strings.HasSuffix(s, "%")
	f, err := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
	if err != nil {
		return 0, fmt.Errorf("--fail: %v", err)
	}
	if pct {
		f /= 100
	}
	if f < 0 || f > 1 {
		return 0, errors.New("--fail: use a share between 0% and 100%")
	}
	return f, nil
}

func (c *Chaos) delay() time.Duration {
	if c.LatencyMax <= c.LatencyMin {
		return c.LatencyMin
	}
	return c.LatencyMin + rand.N(c.LatencyMax-c.LatencyMin)
}

// ---------------------------------------------------------------------------
// Visitor feedback (--feedback)

// Feedback is one comment a visitor left with the widget.
type Feedback struct {
	Time   time.Time
	Tunnel int
	Page   string
	Name   string
	Text   string
	Remote string
}

const (
	maxFeedbackText   = 2000
	maxFeedbackName   = 60
	maxFeedbackPerRun = 500
	maxFeedbackPerIP  = 30
	maxInjectHTML     = 5 << 20
)

// cleanText drops control characters (so nothing can rewrite the owner's
// terminal) and trims to n runes.
func cleanText(s string, n int, multiline bool) string {
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= n {
			break
		}
		if r == '\n' && multiline {
			b.WriteRune(r)
		} else if unicode.IsControl(r) || r == ' ' || r == ' ' || unicode.Is(unicode.Bidi_Control, r) || unicode.Is(unicode.Cf, r) {
			b.WriteRune(' ')
		} else {
			b.WriteRune(r)
		}
		count++
	}
	return strings.TrimSpace(b.String())
}

type feedbackLimiter struct {
	mu    sync.Mutex
	total int
	perIP map[string]int
}

func (l *feedbackLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.perIP == nil {
		l.perIP = map[string]int{}
	}
	if l.total >= maxFeedbackPerRun || l.perIP[ip] >= maxFeedbackPerIP {
		return false
	}
	l.total++
	l.perIP[ip]++
	return true
}

func (h *tunnelHandler) serveFeedback(w http.ResponseWriter, r *http.Request, remote string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	// Only the widget on this link's own pages may post.
	if o := r.Header.Get("Origin"); o != "" && o != "https://"+r.Host && o != "http://"+r.Host {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/json" {
		http.Error(w, "JSON only", http.StatusUnsupportedMediaType)
		return
	}
	var in struct{ Page, Name, Text string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	text := cleanText(in.Text, maxFeedbackText, true)
	if text == "" {
		http.Error(w, "empty comment", http.StatusBadRequest)
		return
	}
	if !h.feedback.allow(remote) {
		http.Error(w, "too many comments", http.StatusTooManyRequests)
		return
	}
	fb := Feedback{Time: time.Now(), Tunnel: h.idx, Page: cleanText(in.Page, 300, false), Name: cleanText(in.Name, maxFeedbackName, false), Text: text, Remote: remote}
	if h.cfg.OnFeedback != nil {
		h.cfg.OnFeedback(fb)
	}
	w.WriteHeader(http.StatusNoContent)
}

// injectSlots bounds how many pages are held in memory for injection at once.
var injectSlots = make(chan struct{}, 8)

var bodyClose = regexp.MustCompile(`(?i)</body\s*>`)

// injectWidget adds the feedback script to HTML pages from the app.
func injectWidget(resp *http.Response) error {
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if ct != "text/html" || resp.Header.Get("Content-Encoding") != "" || resp.StatusCode != http.StatusOK || resp.Request.Method != http.MethodGet {
		return nil
	}
	if resp.ContentLength < 0 || resp.ContentLength > maxInjectHTML {
		return nil // streamed or large pages pass through untouched
	}
	select {
	case injectSlots <- struct{}{}:
		defer func() { <-injectSlots }()
	default:
		return nil // busy: skip the button rather than buffer more pages
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxInjectHTML+1))
	if err != nil {
		return err
	}
	if len(b) > maxInjectHTML { // too big after all: pass it on untouched
		resp.Body = &teeCloser{Reader: io.MultiReader(bytes.NewReader(b), resp.Body), Closer: resp.Body}
		return nil
	}
	resp.Body.Close()
	tag := []byte(`<script src="` + feedbackJS + `" defer></script>`)
	if loc := bodyClose.FindAllIndex(b, -1); len(loc) > 0 {
		at := loc[len(loc)-1][0]
		b = append(b[:at:at], append(tag, b[at:]...)...)
	} else {
		b = append(b, tag...)
	}
	resp.Body = io.NopCloser(bytes.NewReader(b))
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	resp.Header.Del("ETag")
	return nil
}

// widgetJS is the feedback button. It builds its UI with DOM calls inside a
// shadow root, so the app's styles and the visitor's text never mix with HTML.
const widgetJS = `(function(){
if(window.__publiclocalFeedback)return;window.__publiclocalFeedback=1;
var host=document.createElement('div');host.style.cssText='position:fixed;right:16px;bottom:16px;z-index:2147483647';
var root=host.attachShadow({mode:'closed'});
var st=document.createElement('style');st.textContent=':host{all:initial}*{box-sizing:border-box;font:14px system-ui,sans-serif}button{cursor:pointer;border:0;border-radius:999px;background:#111;color:#fff;padding:10px 16px;box-shadow:0 4px 14px rgba(0,0,0,.25)}form{display:none;flex-direction:column;gap:8px;width:280px;max-width:calc(100vw - 32px);background:#fff;color:#111;border:1px solid #ddd;border-radius:12px;padding:14px;box-shadow:0 8px 30px rgba(0,0,0,.2);margin-bottom:8px}textarea,input{width:100%;border:1px solid #ccc;border-radius:8px;padding:8px;color:#111;background:#fff}textarea{height:96px;resize:vertical}small{color:#666}.row{display:flex;gap:8px;justify-content:flex-end}.ghost{background:#eee;color:#111;box-shadow:none}';
var f=document.createElement('form');
var t=document.createElement('textarea');t.placeholder='What do you think of this page?';t.maxLength=2000;t.required=true;
var n=document.createElement('input');n.placeholder='Your name (optional)';n.maxLength=60;
var note=document.createElement('small');note.textContent='Sent to the person who shared this link.';
var row=document.createElement('div');row.className='row';
var c=document.createElement('button');c.type='button';c.className='ghost';c.textContent='Cancel';
var s=document.createElement('button');s.type='submit';s.textContent='Send';
row.append(c,s);f.append(t,n,note,row);
var b=document.createElement('button');b.type='button';b.textContent='Feedback';
root.append(st,f,b);
function show(o){f.style.display=o?'flex':'none';b.style.display=o?'none':'inline-block';if(o)t.focus();}
b.onclick=function(){show(true)};c.onclick=function(){show(false)};
f.onsubmit=function(e){e.preventDefault();s.disabled=true;
fetch('` + feedbackPath + `',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({page:location.pathname,name:n.value,text:t.value})})
.then(function(r){s.disabled=false;if(!r.ok)throw 0;t.value='';show(false);b.textContent='Thanks!';setTimeout(function(){b.textContent='Feedback'},3000)})
.catch(function(){s.disabled=false;note.textContent='Could not send, try again.'});};
(document.body||document.documentElement).appendChild(host);
})();`

// ---------------------------------------------------------------------------
// Live request viewer (--live)

// LiveEvent is what the shared viewer shows: no headers, bodies or queries.
type LiveEvent struct {
	Time   time.Time `json:"time"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Status int       `json:"status"`
	Millis int64     `json:"ms"`
	Note   string    `json:"note,omitempty"`
}

const maxLiveViewers = 20

type liveHub struct {
	mu     sync.Mutex
	subs   map[chan LiveEvent]struct{}
	recent []LiveEvent
}

func (l *liveHub) publish(e LiveEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recent = append(l.recent, e)
	if len(l.recent) > 50 {
		l.recent = l.recent[len(l.recent)-50:]
	}
	for ch := range l.subs {
		select {
		case ch <- e:
		default: // a slow viewer misses events rather than slowing the link
		}
	}
}

func (l *liveHub) subscribe() (chan LiveEvent, []LiveEvent, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.subs == nil {
		l.subs = map[chan LiveEvent]struct{}{}
	}
	if len(l.subs) >= maxLiveViewers {
		return nil, nil, false
	}
	ch := make(chan LiveEvent, 64)
	l.subs[ch] = struct{}{}
	return ch, append([]LiveEvent(nil), l.recent...), true
}

func (l *liveHub) unsubscribe(ch chan LiveEvent) {
	l.mu.Lock()
	delete(l.subs, ch)
	l.mu.Unlock()
}

// LiveURL is the address of the shared viewer for a link.
func LiveURL(linkURL, key string) string { return linkURL + livePath + "?k=" + key }

func (h *tunnelHandler) serveLive(w http.ResponseWriter, r *http.Request) {
	k := r.URL.Query().Get("k")
	if h.cfg.LiveKey == "" || subtle.ConstantTimeCompare([]byte(k), []byte(h.cfg.LiveKey)) != 1 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == livePath {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
		io.WriteString(w, livePage)
		return
	}
	ch, recent, ok := h.live.subscribe()
	if !ok {
		http.Error(w, "too many viewers", http.StatusServiceUnavailable)
		return
	}
	defer h.live.unsubscribe(ch)
	fl, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	send := func(e LiveEvent) bool {
		b, _ := json.Marshal(e)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
			return false
		}
		if fl != nil {
			fl.Flush()
		}
		return true
	}
	for _, e := range recent {
		send(e)
	}
	if fl != nil {
		fl.Flush()
	}
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-ch:
			if !send(e) {
				return
			}
		case <-ping.C:
			if _, err := io.WriteString(w, ": ping\n\n"); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
	}
}

const livePage = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Live requests · PublicLocal</title>
<style>:root{color-scheme:light dark;--bg:#fff;--fg:#111;--mut:#666;--line:#e5e5e5;--ok:#15803d;--warn:#b45309;--bad:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f12;--fg:#e8e8e8;--mut:#999;--line:#262a30;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
header{padding:16px;border-bottom:1px solid var(--line);font-family:system-ui,sans-serif}h1{font-size:16px;margin:0}p{margin:4px 0 0;color:var(--mut)}
#dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--mut);margin-right:6px}#dot.on{background:var(--ok)}
table{width:100%;border-collapse:collapse}td{padding:6px 16px;border-bottom:1px solid var(--line);white-space:nowrap}td.p{white-space:normal;word-break:break-all;width:100%}
.s2{color:var(--ok)}.s3{color:var(--mut)}.s4{color:var(--warn)}.s5{color:var(--bad)}.m{color:var(--mut)}#empty{padding:24px 16px;color:var(--mut)}</style></head>
<body><header><h1><span id="dot"></span>Live requests</h1><p>Requests to this link as they happen. Paths only: no headers, bodies or query strings.</p></header>
<div id="empty">Waiting for requests…</div><table><tbody id="rows"></tbody></table>
<script>(function(){var rows=document.getElementById('rows'),empty=document.getElementById('empty'),dot=document.getElementById('dot');
function td(t,c){var d=document.createElement('td');d.textContent=t;if(c)d.className=c;return d}
function add(e){empty.style.display='none';var tr=document.createElement('tr');var t=new Date(e.time);
tr.append(td(t.toLocaleTimeString(),'m'),td(e.method),td(e.path+(e.note?'  ['+e.note+']':''),'p'),td(String(e.status),'s'+String(e.status)[0]),td(e.ms+' ms','m'));
rows.insertBefore(tr,rows.firstChild);while(rows.children.length>300)rows.removeChild(rows.lastChild)}
var es=new EventSource('` + liveEvents + `'+location.search);es.onopen=function(){dot.className='on'};es.onerror=function(){dot.className=''};
es.onmessage=function(m){try{add(JSON.parse(m.data))}catch(_){}}})();</script></body></html>`
