package server

import (
	"html/template"
	"net/http"
	"strconv"
)

// Visitors who hit a link that is offline, expired or whose app is not
// answering get a page that says so, with the right status code: 503 with
// Retry-After while the owner's computer is disconnected, 404 once the link
// is gone, 502 when the app behind it fails. API clients get plain text.

type statusPage struct {
	Code    int
	Title   string
	Message string
	Hint    string
	Host    string
	Retry   int // seconds; > 0 adds Retry-After and a meta refresh
	Site    string
}

func (s *Server) linkOffline(w http.ResponseWriter, r *http.Request, host string) {
	s.statusPage(w, r, statusPage{
		Code: http.StatusServiceUnavailable, Retry: 20, Host: host,
		Title:   "This link is offline right now",
		Message: "The computer behind this link is not connected at the moment. The link is still valid, so it may come back shortly.",
		Hint:    "This page refreshes on its own every 20 seconds.",
	})
}

func (s *Server) linkGone(w http.ResponseWriter, r *http.Request, host string) {
	s.statusPage(w, r, statusPage{
		Code: http.StatusNotFound, Host: host,
		Title:   "This temporary link has expired",
		Message: "Links on this server are short-lived by design: they point at an app on a developer's own computer and stop working after a while, or when the developer closes them.",
		Hint:    "If someone sent you this link, ask them for a fresh one.",
	})
}

func (s *Server) appDown(w http.ResponseWriter, r *http.Request, host string) {
	s.statusPage(w, r, statusPage{
		Code: http.StatusBadGateway, Retry: 10, Host: host,
		Title:   "The app behind this link is not responding",
		Message: "The link is connected, but nothing answered on the developer's computer. The app may be restarting or listening on a different port.",
		Hint:    "Try again in a moment.",
	})
}

func (s *Server) statusPage(w http.ResponseWriter, r *http.Request, p statusPage) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	if p.Retry > 0 {
		h.Set("Retry-After", strconv.Itoa(p.Retry))
	}
	if !isNavigation(r) {
		h.Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(p.Code)
		w.Write([]byte("publiclocal: " + p.Title + "\n"))
		return
	}
	p.Site = s.baseURL()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
	w.WriteHeader(p.Code)
	if r.Method != http.MethodHead {
		statusTmpl.Execute(w, p)
	}
}

var statusTmpl = template.Must(template.New("status").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
{{if .Retry}}<meta http-equiv="refresh" content="{{.Retry}}">{{end}}
<title>{{.Title}} · PublicLocal</title>
<style>
  :root { color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --fg:#1d2330; --muted:#5b6475; --line:#e2e5ea; --accent:#2557e8; --soft:#e8eefc; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0f1218; --card:#171b23; --fg:#e7eaf0; --muted:#9aa3b2; --line:#2a303b; --accent:#5b8cff; --soft:#15213f; } }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px; background:var(--bg); color:var(--fg); font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  main { max-width:540px; width:100%; background:var(--card); border:1px solid var(--line); border-radius:14px; padding:28px; text-align:center; }
  .mark { width:56px; height:56px; border-radius:14px; background:var(--soft); color:var(--accent); display:inline-grid; place-items:center; margin-bottom:14px; }
  h1 { font-size:21px; margin:0 0 8px; }
  p { margin:0 0 10px; color:var(--muted); }
  .host { font-family:ui-monospace,Consolas,monospace; font-size:14px; word-break:break-all; color:var(--muted); margin-bottom:16px; }
  .code { font-size:12px; color:var(--muted); margin-top:18px; }
  footer { margin-top:22px; padding-top:16px; border-top:1px solid var(--line); font-size:13px; color:var(--muted); }
  footer a { color:var(--accent); text-decoration:none; font-weight:600; }
</style>
</head>
<body>
<main>
  <div class="mark"><svg width="28" height="28" viewBox="0 0 32 32" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round"><path d="M9 20a7 7 0 0 1 14 0"/><circle cx="16" cy="20" r="2.5" fill="currentColor" stroke="none"/></svg></div>
  <div class="host">{{.Host}}</div>
  <h1>{{.Title}}</h1>
  <p>{{.Message}}</p>
  <p>{{.Hint}}</p>
  <div class="code">HTTP {{.Code}}</div>
  <footer>This was a temporary link made with <a href="{{.Site}}/?ref=link">PublicLocal</a>, a free, open-source way to share localhost. <a href="{{.Site}}/?ref=link">Make your own →</a></footer>
</main>
</body>
</html>
`))
