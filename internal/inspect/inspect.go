// Package inspect keeps the requests a tunnel served and shows them on a
// local web page, where any of them can be replayed against the local app.
// It is the webhook workbench: wait for Stripe to call once, then hit
// "replay" while fixing the handler.
package inspect

import (
	"bytes"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sevenoways/publiclocal/internal/client"
)

// MaxBody is how much of each request and response body is kept.
const MaxBody = 256 << 10

// Entry is one recorded request.
type Entry struct {
	ID       int       `json:"id"`
	Time     time.Time `json:"time"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Host     string    `json:"host"`
	Status   int       `json:"status"`
	Millis   int64     `json:"ms"`
	Remote   string    `json:"remote"`
	Bytes    int64     `json:"bytes"`
	Local    string    `json:"local"`
	ReplayOf int       `json:"replay_of,omitempty"`

	ReqHeader     http.Header `json:"req_header"`
	ReqBody       string      `json:"req_body"`
	ReqTruncated  bool        `json:"req_truncated,omitempty"`
	RespHeader    http.Header `json:"resp_header"`
	RespBody      string      `json:"resp_body"`
	RespTruncated bool        `json:"resp_truncated,omitempty"`
	ReqBinary     bool        `json:"req_binary,omitempty"`
	RespBinary    bool        `json:"resp_binary,omitempty"`
}

// Store keeps the most recent requests.
type Store struct {
	mu      sync.Mutex
	entries []*Entry
	next    int
	limit   int
}

func NewStore(limit int) *Store { return &Store{limit: limit} }

// Add records a captured request.
func (s *Store) Add(c client.Captured) *Entry {
	e := &Entry{
		Time: c.Time, Method: c.Method, Path: c.Path, Host: c.Host, Status: c.Status, Millis: c.Duration.Milliseconds(),
		Remote: c.Remote, Bytes: c.Bytes, Local: c.Local,
		ReqHeader: c.ReqHeader, ReqTruncated: c.ReqTruncated, RespHeader: c.RespHeader, RespTruncated: c.RespTruncated,
	}
	e.ReqBody, e.ReqBinary = textOrMark(c.ReqBody)
	e.RespBody, e.RespBinary = textOrMark(c.RespBody)
	s.mu.Lock()
	s.next++
	e.ID = s.next
	s.entries = append(s.entries, e)
	if len(s.entries) > s.limit {
		s.entries = s.entries[len(s.entries)-s.limit:]
	}
	s.mu.Unlock()
	return e
}

func textOrMark(b []byte) (string, bool) {
	if len(b) == 0 {
		return "", false
	}
	for _, c := range b[:min(len(b), 512)] {
		if c == 0 || (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
			return "(binary, " + strconv.Itoa(len(b)) + " bytes)", true
		}
	}
	return string(b), false
}

// List returns entries newest first.
func (s *Store) List() []*Entry {
	s.mu.Lock()
	out := make([]*Entry, len(s.entries))
	copy(out, s.entries)
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}

func (s *Store) Get(id int) *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.entries {
		if e.ID == id {
			return e
		}
	}
	return nil
}

// Summary describes what a session served, for the message at exit.
type Summary struct {
	Requests int
	Visitors int
	Bytes    int64
	TopPaths []string
}

func (s *Store) Summary() Summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	sum := Summary{}
	seen := map[string]bool{}
	paths := map[string]int{}
	for _, e := range s.entries {
		if e.ReplayOf != 0 {
			continue
		}
		sum.Requests++
		sum.Bytes += e.Bytes
		if e.Remote != "" && !seen[e.Remote] {
			seen[e.Remote] = true
			sum.Visitors++
		}
		p := e.Path
		if i := strings.IndexByte(p, '?'); i >= 0 {
			p = p[:i]
		}
		paths[p]++
	}
	type kv struct {
		p string
		n int
	}
	var kvs []kv
	for p, n := range paths {
		kvs = append(kvs, kv{p, n})
	}
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].n > kvs[j].n || (kvs[i].n == kvs[j].n && kvs[i].p < kvs[j].p) })
	for i, k := range kvs {
		if i == 3 {
			break
		}
		sum.TopPaths = append(sum.TopPaths, k.p+" ("+strconv.Itoa(k.n)+")")
	}
	return sum
}

// Replay sends a recorded request to the local app again and records the result.
func (s *Store) Replay(id int) (*Entry, error) {
	orig := s.Get(id)
	if orig == nil {
		return nil, errNotFound
	}
	if orig.ReqBinary {
		return nil, errBinary
	}
	req, err := http.NewRequest(orig.Method, "http://"+orig.Local+orig.Path, strings.NewReader(orig.ReqBody))
	if err != nil {
		return nil, err
	}
	for k, vs := range orig.ReqHeader {
		if k == "Content-Length" {
			continue
		}
		req.Header[k] = vs
	}
	req.Host = orig.Host
	start := time.Now()
	resp, err := (&http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	c := client.Captured{Time: start, Local: orig.Local, Method: orig.Method, Path: orig.Path, Host: orig.Host, Remote: "replay", ReqHeader: orig.ReqHeader, ReqBody: []byte(orig.ReqBody)}
	if err != nil {
		c.Status, c.Duration = http.StatusBadGateway, time.Since(start)
		c.RespBody = []byte("replay failed: " + err.Error())
	} else {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBody+1))
		resp.Body.Close()
		c.Status, c.Duration, c.RespHeader = resp.StatusCode, time.Since(start), resp.Header
		if len(body) > MaxBody {
			body, c.RespTruncated = body[:MaxBody], true
		}
		c.RespBody, c.Bytes = body, int64(len(body))
	}
	e := s.Add(c)
	e.ReplayOf = id
	return e, nil
}

var (
	errNotFound = &inspectError{"no such request"}
	errBinary   = &inspectError{"binary request bodies cannot be replayed"}
)

type inspectError struct{ msg string }

func (e *inspectError) Error() string { return e.msg }

// Handler serves the inspector page and its small API. links returns the
// public URLs to show in the header.
func (s *Store) Handler(links func() []string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/requests", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.List())
	})
	mux.HandleFunc("POST /api/replay/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.Atoi(r.PathValue("id"))
		e, err := s.Replay(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, e)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
		page.Execute(w, struct{ Links []string }{links()})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Local only; refuse anything a web page on another origin sends.
		if o := r.Header.Get("Origin"); o != "" && !strings.HasPrefix(o, "http://"+r.Host) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(v)
	w.Header().Set("Content-Type", "application/json")
	w.Write(buf.Bytes())
}

var page = template.Must(template.New("inspect").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PublicLocal inspector</title>
<style>
  :root { color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --fg:#1d2330; --muted:#5b6475; --line:#e2e5ea; --accent:#2557e8; --ok:#157a3c; --bad:#b42318; --code:#0e1320; --codefg:#e6ebf5; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0f1218; --card:#171b23; --fg:#e7eaf0; --muted:#9aa3b2; --line:#2a303b; --accent:#5b8cff; --ok:#4ccf7f; --bad:#ff7a6e; } }
  * { box-sizing:border-box } body { margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; height:100vh; display:flex; flex-direction:column }
  header { display:flex; align-items:center; gap:14px; padding:10px 16px; border-bottom:1px solid var(--line); background:var(--card) }
  header b { font-size:15px } header .links { color:var(--muted); font-family:ui-monospace,Consolas,monospace; font-size:13px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap }
  header input { margin-left:auto; font:inherit; padding:6px 10px; border:1px solid var(--line); border-radius:8px; background:var(--bg); color:var(--fg); width:220px }
  main { flex:1; display:grid; grid-template-columns: 420px 1fr; min-height:0 }
  @media (max-width:900px) { main { grid-template-columns:1fr } #detail { display:none } main.open #list { display:none } main.open #detail { display:block } }
  #list { overflow:auto; border-right:1px solid var(--line) } #detail { overflow:auto; padding:16px 20px }
  .row { display:grid; grid-template-columns: 58px 1fr 44px 60px; gap:8px; padding:9px 14px; border-bottom:1px solid var(--line); cursor:pointer; font-family:ui-monospace,Consolas,monospace; font-size:13px }
  .row:hover, .row.sel { background:var(--card) } .row .m { font-weight:700 } .row .p { overflow:hidden; text-overflow:ellipsis; white-space:nowrap } .row .t { color:var(--muted); text-align:right }
  .ok { color:var(--ok) } .bad { color:var(--bad) } .replay { color:var(--accent); font-size:11px }
  .empty { padding:40px 20px; color:var(--muted); text-align:center }
  h2 { font-size:16px; margin:0 0 4px; font-family:ui-monospace,Consolas,monospace; word-break:break-all } .meta { color:var(--muted); margin-bottom:12px }
  button { font:inherit; font-weight:600; padding:7px 14px; border-radius:8px; border:1px solid var(--accent); background:var(--accent); color:#fff; cursor:pointer } button.quiet { background:transparent; color:var(--fg); border-color:var(--line) }
  h3 { font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:18px 0 6px }
  pre { background:var(--code); color:var(--codefg); border-radius:10px; padding:12px 14px; overflow:auto; font-size:12.5px; margin:0; max-height:40vh; white-space:pre-wrap; word-break:break-all }
  .back { display:none } @media (max-width:900px) { .back { display:inline-block; margin-bottom:10px } }
</style></head>
<body>
<header><b>PublicLocal inspector</b><span class="links">{{range .Links}}{{.}} {{end}}</span><input id="q" placeholder="filter path or method"></header>
<main id="main">
  <div id="list"><div class="empty">Waiting for requests… send one to your link and it appears here.</div></div>
  <div id="detail"><div class="empty">Select a request to see headers and bodies, and to replay it.</div></div>
</main>
<script>
(function(){
  var list=document.getElementById('list'), detail=document.getElementById('detail'), q=document.getElementById('q'), main=document.getElementById('main');
  var items=[], sel=null;
  function cls(s){return s>=200&&s<400?'ok':(s>=400?'bad':'')}
  function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
  function hdrs(h){var o=[];Object.keys(h||{}).sort().forEach(function(k){(h[k]||[]).forEach(function(v){o.push(k+': '+v)})});return o.join('\n')}
  function render(){
    var f=q.value.toLowerCase(), rows=items.filter(function(e){return !f||(e.method+' '+e.path).toLowerCase().indexOf(f)>=0});
    if(!rows.length){list.innerHTML='<div class="empty">'+(items.length?'No requests match.':'Waiting for requests… send one to your link and it appears here.')+'</div>';return}
    list.innerHTML=rows.map(function(e){return '<div class="row'+(sel===e.id?' sel':'')+'" data-id="'+e.id+'"><span class="m">'+esc(e.method)+'</span><span class="p">'+esc(e.path)+(e.replay_of?' <span class="replay">replay of #'+e.replay_of+'</span>':'')+'</span><span class="'+cls(e.status)+'">'+e.status+'</span><span class="t">'+e.ms+' ms</span></div>'}).join('');
  }
  function show(e){
    sel=e.id; main.classList.add('open'); render();
    detail.innerHTML='<button class="quiet back" id="back">← Back</button><h2>'+esc(e.method)+' '+esc(e.path)+'</h2><div class="meta">'+esc(e.host)+' · <span class="'+cls(e.status)+'">'+e.status+'</span> · '+e.ms+' ms · '+e.bytes+' B · from '+esc(e.remote)+' · '+new Date(e.time).toLocaleTimeString()+(e.replay_of?' · replay of #'+e.replay_of:'')+'</div>'
      +'<button id="replay"'+(e.req_binary?' disabled':'')+'>Replay against localhost</button>'
      +'<h3>Request headers</h3><pre>'+esc(hdrs(e.req_header))+'</pre>'
      +(e.req_body?'<h3>Request body'+(e.req_truncated?' (truncated)':'')+'</h3><pre>'+esc(e.req_body)+'</pre>':'')
      +'<h3>Response headers</h3><pre>'+esc(hdrs(e.resp_header))+'</pre>'
      +(e.resp_body?'<h3>Response body'+(e.resp_truncated?' (truncated)':'')+'</h3><pre>'+esc(e.resp_body)+'</pre>':'');
    document.getElementById('replay').onclick=function(){fetch('/api/replay/'+e.id,{method:'POST'}).then(function(r){return r.ok?r.json():r.text().then(function(t){throw new Error(t)})}).then(function(n){load().then(function(){var m=items.filter(function(x){return x.id===n.id})[0];if(m)show(m)})}).catch(function(err){alert(err.message)})};
    var b=document.getElementById('back'); if(b) b.onclick=function(){main.classList.remove('open')};
  }
  list.addEventListener('click',function(ev){var r=ev.target.closest('.row');if(!r)return;var e=items.filter(function(x){return x.id==r.dataset.id})[0];if(e)show(e)});
  q.addEventListener('input',render);
  function load(){return fetch('/api/requests').then(function(r){return r.json()}).then(function(d){items=d;render()}).catch(function(){})}
  load(); setInterval(load,1000);
})();
</script>
</body></html>`))
