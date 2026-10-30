package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"
)

// Visitors who hit a link that is offline, expired or whose app is not
// answering get a page that says so, with the right status code: 503 with
// Retry-After while the owner's computer is disconnected, 404 once the link
// is gone, 502 when the app behind it fails. API clients get plain text.
// The pages also show what the link did: when it was live and how much
// traffic it saw.

const (
	statusPath = "/.publiclocal/status"
	badgePath  = "/.publiclocal/badge.svg"
)

// linkBadge answers a small status badge, for READMEs and pull requests.
func (s *Server) linkBadge(w http.ResponseWriter, sub string) {
	s.mu.RLock()
	rt, res := s.hosts[sub], s.reservations[sub]
	s.mu.RUnlock()
	state, color := "expired", "#9aa3b2"
	switch {
	case rt != nil:
		state, color = "online", "#2ea44f"
	case res != nil && !res.expired(time.Now()):
		state, color = "offline", "#dbab09"
	}
	const lw, rw = 58, 54
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="20" role="img" aria-label="preview: %s">
<linearGradient id="s" x2="0" y2="100%%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
<clipPath id="r"><rect width="%d" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)"><rect width="%d" height="20" fill="#555"/><rect x="%d" width="%d" height="20" fill="%s"/><rect width="%d" height="20" fill="url(#s)"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="%d" y="14">preview</text><text x="%d" y="14">%s</text></g></svg>`,
		lw+rw, state, lw+rw, lw, lw, rw, color, lw+rw, lw/2, lw+rw/2, state)
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-cache, max-age=0")
	w.Write([]byte(svg))
}

type statusPage struct {
	Code    int
	Title   string
	Message string
	Hint    string
	Host    string
	Retry   int // seconds; > 0 adds Retry-After and a meta refresh
	Site    string
	Stats   []statRow
}

type statRow struct{ Label, Value string }

func (s *Server) linkOffline(w http.ResponseWriter, r *http.Request, host string, res *reservation) {
	s.mu.RLock()
	req, bytes, vis := res.live(nil)
	last, expires := res.LastOnline, res.Expires
	s.mu.RUnlock()
	p := statusPage{
		Code: http.StatusServiceUnavailable, Retry: 20, Host: host,
		Title:   "This link is offline right now",
		Message: "The computer behind this link is not connected at the moment. The link is still valid, so it may come back shortly.",
		Hint:    "This page refreshes on its own every 20 seconds.",
	}
	if !last.IsZero() {
		p.Stats = append(p.Stats, statRow{"Last online", ago(last)})
	}
	if !expires.IsZero() {
		p.Stats = append(p.Stats, statRow{"Link valid until", expires.UTC().Format("Mon 2 Jan 2006, 15:04 UTC")})
	}
	p.Stats = append(p.Stats, trafficRows(req, bytes, vis)...)
	s.statusPage(w, r, p)
}

func (s *Server) linkGone(w http.ResponseWriter, r *http.Request, host string, past *reservation) {
	p := statusPage{
		Code: http.StatusNotFound, Host: host,
		Title:   "This temporary link has expired",
		Message: "Links on this server are short-lived by design: they point at an app on a developer's own computer and stop working after a while, or when the developer closes them.",
		Hint:    "If someone sent you this link, ask them for a fresh one.",
	}
	if past != nil {
		until := past.LastOnline
		if until.IsZero() || (!past.Expires.IsZero() && past.Expires.Before(until)) {
			until = past.Expires
		}
		p.Stats = append(p.Stats, statRow{"Live from", past.Created.UTC().Format("Mon 2 Jan 2006, 15:04 UTC")})
		if !until.IsZero() {
			p.Stats = append(p.Stats, statRow{"Until", until.UTC().Format("Mon 2 Jan 2006, 15:04 UTC") + " (" + ago(until) + ")"})
		}
		p.Stats = append(p.Stats, trafficRows(past.Requests, past.Bytes, past.Visitors)...)
	}
	s.statusPage(w, r, p)
}

func (s *Server) appDown(w http.ResponseWriter, r *http.Request, host string) {
	s.statusPage(w, r, statusPage{
		Code: http.StatusBadGateway, Retry: 10, Host: host,
		Title:   "The app behind this link is not responding",
		Message: "The link is connected, but nothing answered on the developer's computer. The app may be restarting or listening on a different port.",
		Hint:    "Try again in a moment.",
	})
}

// pastLink returns the summary of an expired link, if one is still kept.
func (s *Server) pastLink(sub string) *reservation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.history[sub]
}

// linkStatus answers /.publiclocal/status on a link with JSON, for people
// and scripts that want to know whether a link is up without hitting the app.
func (s *Server) linkStatus(w http.ResponseWriter, sub string) {
	s.mu.RLock()
	rt, res, past := s.hosts[sub], s.reservations[sub], s.history[sub]
	if res != nil && res.expired(time.Now()) {
		res = nil
	}
	out := map[string]any{"name": sub, "online": rt != nil}
	switch {
	case res != nil:
		req, bytes, vis := res.live(rt)
		out["state"] = map[bool]string{true: "online", false: "offline"}[rt != nil]
		out["created"] = res.Created
		if !res.Expires.IsZero() {
			out["expires"] = res.Expires
		}
		if rt == nil && !res.LastOnline.IsZero() {
			out["last_online"] = res.LastOnline
		}
		out["requests"], out["bytes"], out["visitors"] = req, bytes, vis
	case past != nil:
		out["state"] = "expired"
		out["created"], out["expires"] = past.Created, past.Expires
		if !past.LastOnline.IsZero() {
			out["last_online"] = past.LastOnline
		}
		out["requests"], out["bytes"], out["visitors"] = past.Requests, past.Bytes, past.Visitors
	default:
		out["state"] = "unknown"
	}
	s.mu.RUnlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if out["state"] == "unknown" {
		w.WriteHeader(http.StatusNotFound)
	}
	writeJSON(w, out)
}

func trafficRows(requests, bytes int64, visitors int) []statRow {
	if requests == 0 {
		return []statRow{{"Traffic", "no requests served"}}
	}
	v := fmt.Sprintf("%s requests from %s visitor%s · %s", group(requests), group(int64(visitors)), plural(visitors), humanBytes(bytes))
	return []statRow{{"Traffic", v}}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func group(n int64) string {
	s := strconv.FormatInt(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func humanBytes(b int64) string {
	const k = 1024
	switch {
	case b >= k*k*k:
		return fmt.Sprintf("%.1f GB", float64(b)/(k*k*k))
	case b >= k*k:
		return fmt.Sprintf("%.1f MB", float64(b)/(k*k))
	case b >= k:
		return fmt.Sprintf("%.0f KB", float64(b)/k)
	}
	return fmt.Sprintf("%d B", b)
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days ago", int(d.Hours()/24))
	}
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
  main { max-width:560px; width:100%; background:var(--card); border:1px solid var(--line); border-radius:14px; padding:28px; text-align:center; }
  .mark { width:56px; height:56px; border-radius:14px; background:var(--soft); color:var(--accent); display:inline-grid; place-items:center; margin-bottom:14px; }
  h1 { font-size:21px; margin:0 0 8px; }
  p { margin:0 0 10px; color:var(--muted); }
  .host { font-family:ui-monospace,Consolas,monospace; font-size:14px; word-break:break-all; color:var(--muted); margin-bottom:16px; }
  dl { display:grid; grid-template-columns:auto 1fr; gap:6px 14px; text-align:left; margin:18px 0 0; padding:14px 16px; background:var(--bg); border-radius:10px; font-size:14px; }
  dt { color:var(--muted); white-space:nowrap; } dd { margin:0; }
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
  {{if .Stats}}<dl>{{range .Stats}}<dt>{{.Label}}</dt><dd>{{.Value}}</dd>{{end}}</dl>{{end}}
  <div class="code">HTTP {{.Code}}</div>
  <footer>This was a temporary link made with <a href="{{.Site}}/?ref=link">PublicLocal</a>, a free, open-source way to share localhost. <a href="{{.Site}}/?ref=link">Make your own →</a></footer>
</main>
</body>
</html>
`))
