package server

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

// The warning page stands between browsers and tunnel content, so a link to a
// tunnel cannot pass as a trusted site without the visitor being told what it
// is. Visitors continue after a short countdown; a cookie remembers the choice
// for that tunnel. API clients, webhooks and curl never see it.
const (
	warningCookie = "publiclocal_warning_ok"
	continuePath  = "/.publiclocal/continue"
	skipHeader    = "PublicLocal-Skip-Warning"
)

func needsWarning(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get(skipHeader) != "" {
		return false
	}
	if !strings.Contains(r.UserAgent(), "Mozilla") || !strings.Contains(r.Header.Get("Accept"), "text/html") {
		return false
	}
	_, err := r.Cookie(warningCookie)
	return err != nil
}

func (s *Server) serveWarning(w http.ResponseWriter, r *http.Request, host string) {
	data := struct {
		Host, Next, Abuse string
	}{host, r.URL.RequestURI(), abuseLink(s.cfg.AbuseContact, host)}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'")
	h.Set("X-Frame-Options", "DENY")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		warningPage.Execute(w, data)
	}
}

func (s *Server) acceptWarning(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	next := r.PostFormValue("next")
	// Only same-site paths, so the form cannot be used as an open redirect.
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		next = "/"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     warningCookie,
		Value:    "1",
		Path:     "/",
		MaxAge:   24 * 60 * 60,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// stripWarningCookie keeps our cookie from reaching the tunnelled app.
func stripWarningCookie(r *http.Request) {
	if !strings.Contains(r.Header.Get("Cookie"), warningCookie) {
		return
	}
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != warningCookie {
			r.AddCookie(c)
		}
	}
}

func abuseLink(contact, host string) string {
	switch {
	case strings.HasPrefix(contact, "mailto:"):
		return contact + "?subject=" + url.QueryEscape("Abuse report: "+host)
	case strings.HasPrefix(contact, "https://"), strings.HasPrefix(contact, "http://"):
		sep := "?"
		if strings.Contains(contact, "?") {
			sep = "&"
		}
		return contact + sep + "host=" + url.QueryEscape(host)
	}
	return ""
}

var warningPage = template.Must(template.New("warning").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Temporary tunnel: {{.Host}}</title>
<style>
  :root { color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --fg:#1d2330; --muted:#5b6475; --line:#e2e5ea; --warn:#9a5b00; --warnbg:#fff4e0; --btn:#1d4ed8; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0f1218; --card:#171b23; --fg:#e7eaf0; --muted:#9aa3b2; --line:#2a303b; --warn:#ffcc80; --warnbg:#2b2112; --btn:#3b82f6; } }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px; background:var(--bg); color:var(--fg); font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  main { max-width:560px; width:100%; background:var(--card); border:1px solid var(--line); border-radius:14px; padding:28px; }
  .tag { display:inline-block; font-size:13px; font-weight:600; color:var(--warn); background:var(--warnbg); border-radius:999px; padding:3px 10px; }
  h1 { font-size:22px; margin:14px 0 6px; }
  .host { font-family:ui-monospace,Consolas,monospace; font-size:15px; word-break:break-all; color:var(--muted); }
  ul { padding-left:20px; margin:16px 0; }
  li { margin:6px 0; }
  button { width:100%; margin-top:8px; padding:12px; font:inherit; font-weight:600; color:#fff; background:var(--btn); border:0; border-radius:10px; cursor:pointer; }
  button:disabled { opacity:.55; cursor:wait; }
  footer { margin-top:18px; font-size:13px; color:var(--muted); display:flex; flex-wrap:wrap; gap:6px 16px; justify-content:space-between; }
  a { color:inherit; }
</style>
</head>
<body>
<main>
  <span class="tag">Temporary tunnel</span>
  <h1>You are visiting a temporary developer link</h1>
  <div class="host">{{.Host}}</div>
  <ul>
    <li>This page is served from someone's own computer through <strong>PublicLocal</strong>, a free tunnel for testing and demos. Links stop working after a few hours.</li>
    <li>It is <strong>not</strong> affiliated with any company or brand it may show.</li>
    <li><strong>Do not enter passwords, payment details or personal information</strong> unless you know and trust whoever sent you this link.</li>
  </ul>
  <form method="post" action="/.publiclocal/continue">
    <input type="hidden" name="next" value="{{.Next}}">
    <button id="go" type="submit">Continue to site</button>
  </form>
  <footer>
    <span>Developers: send the header <code>PublicLocal-Skip-Warning: 1</code> to skip this page.</span>
    {{if .Abuse}}<a href="{{.Abuse}}" rel="nofollow">Report abuse</a>{{end}}
  </footer>
</main>
<script>
  (function () {
    var b = document.getElementById("go"), n = 3;
    b.disabled = true;
    (function tick() {
      if (n === 0) { b.disabled = false; b.textContent = "Continue to site"; return; }
      b.textContent = "Continue in " + n + "…";
      n--; setTimeout(tick, 1000);
    })();
  })();
</script>
</body>
</html>
`))
