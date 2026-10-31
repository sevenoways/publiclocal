package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Login works like a device login: the CLI asks for a login and shows a code,
// the user opens the login page, types the code, and signs in with GitHub;
// the CLI polls until that has happened and then holds an account token it
// sends in its Hello.
//
// Typing the code (rather than the page showing it) means a login link sent
// to someone else is useless without the code from the attacker's terminal,
// and a cookie set when the code is accepted ties the GitHub callback to the
// same browser.
//
//	POST /api/login/start   -> {id, secret, code}
//	GET  /login?id=ID       page asking for the code
//	POST /login             {id, code} -> redirects to GitHub, sets a cookie
//	GET  /auth/callback     <- GitHub redirects back here
//	POST /api/login/poll    {id, secret} -> {token, login} once signed in
//	GET  /api/me            Authorization: Bearer TOKEN -> {login, links}
//	POST /api/extend        Authorization: Bearer TOKEN, {name} -> {expires}
//	POST /api/logout        Authorization: Bearer TOKEN

type pendingLogin struct {
	code       string
	secretHash string
	ipKey      string
	created    time.Time
	attempts   int
	confirmed  bool
	browser    string // hash of the cookie set when the code was accepted
	token      string // set once the user has signed in
	login      string
	err        string
}

const (
	loginTTL         = 10 * time.Minute
	loginCookie      = "publiclocal_login"
	maxCodeAttempts  = 5
	maxPendingPerIP  = 20
	maxPendingLogins = 10000
	tokenMaxAge      = 180 * 24 * time.Hour
)

func (s *Server) loginEnabled() bool { return s.cfg.GitHubClientID != "" }

// serveAccountAPI handles the login and account endpoints on the bare domain.
// It reports whether it handled the request.
func (s *Server) serveAccountAPI(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/api/login/start", "/api/login/poll", "/login", "/auth/callback", "/api/me", "/api/extend", "/api/logout", "/visitor-login":
	default:
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.loginEnabled() {
		apiError(w, http.StatusNotFound, "login is not enabled on this server")
		return true
	}
	switch r.URL.Path {
	case "/api/login/start":
		s.loginStart(w, r)
	case "/api/login/poll":
		s.loginPoll(w, r)
	case "/login":
		if r.Method == http.MethodPost {
			s.loginConfirm(w, r)
		} else {
			s.loginPage(w, r)
		}
	case "/auth/callback":
		if st := r.URL.Query().Get("state"); strings.HasPrefix(st, "v") {
			s.visitorCallback(w, r, st, r.URL.Query().Get("code"))
		} else {
			s.loginCallback(w, r)
		}
	case "/visitor-login":
		s.visitorLogin(w, r)
	case "/api/me":
		s.me(w, r)
	case "/api/extend":
		s.extend(w, r)
	case "/api/logout":
		s.logout(w, r)
	}
	return true
}

func apiError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) baseURL() string { return s.scheme + "://" + s.cfg.Domain }

func (s *Server) loginStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	key := ipKey(r.RemoteAddr)
	if !s.loginLimit.allow(key) {
		apiError(w, http.StatusTooManyRequests, "too many login attempts; try again in a minute")
		return
	}
	id, secret := newSecret()[:16], newSecret()
	code := strings.ToUpper(randomName(4, 4) + "-" + randomName(4, 4))
	s.mu.Lock()
	now := time.Now()
	mine := 0
	for k, p := range s.logins {
		if now.Sub(p.created) > loginTTL {
			delete(s.logins, k)
		} else if p.ipKey == key {
			mine++
		}
	}
	if mine >= maxPendingPerIP || len(s.logins) >= maxPendingLogins {
		s.mu.Unlock()
		apiError(w, http.StatusTooManyRequests, "too many logins in progress; try again shortly")
		return
	}
	s.logins[id] = &pendingLogin{code: code, secretHash: hashSecret(secret), ipKey: key, created: now}
	s.mu.Unlock()
	writeJSON(w, map[string]string{"id": id, "secret": secret, "code": code, "url": s.baseURL() + "/login?id=" + id})
}

func (s *Server) pending(id string) *pendingLogin {
	s.mu.RLock()
	p := s.logins[id]
	s.mu.RUnlock()
	if p == nil || time.Since(p.created) > loginTTL {
		return nil
	}
	return p
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if s.pending(id) == nil {
		loginResult(w, http.StatusBadRequest, "This login link has expired", "Run publiclocal login again.")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	confirmTmpl.Execute(w, struct {
		ID, Error string
	}{id, r.URL.Query().Get("error")})
}

// loginConfirm checks the code the user typed, then sends them to GitHub.
func (s *Server) loginConfirm(w http.ResponseWriter, r *http.Request) {
	id := r.PostFormValue("id")
	typed := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "_", "").Replace(r.PostFormValue("code")))
	s.mu.Lock()
	p := s.logins[id]
	if p == nil || time.Since(p.created) > loginTTL {
		s.mu.Unlock()
		loginResult(w, http.StatusBadRequest, "This login link has expired", "Run publiclocal login again.")
		return
	}
	p.attempts++
	want := strings.ReplaceAll(p.code, "-", "")
	if p.attempts > maxCodeAttempts {
		delete(s.logins, id)
		s.mu.Unlock()
		loginResult(w, http.StatusForbidden, "Too many wrong codes", "Run publiclocal login again to get a new one.")
		return
	}
	if subtle.ConstantTimeCompare([]byte(typed), []byte(want)) != 1 {
		s.mu.Unlock()
		http.Redirect(w, r, "/login?id="+url.QueryEscape(id)+"&error=wrong", http.StatusSeeOther)
		return
	}
	nonce := newSecret()
	p.confirmed = true
	p.browser = hashSecret(nonce)
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: loginCookie, Value: nonce, Path: "/", MaxAge: int(loginTTL.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	q := url.Values{
		"client_id":    {s.cfg.GitHubClientID},
		"redirect_uri": {s.baseURL() + "/auth/callback"},
		"state":        {id},
		"allow_signup": {"false"},
	}
	http.Redirect(w, r, s.cfg.GitHubURL+"/login/oauth/authorize?"+q.Encode(), http.StatusSeeOther)
}

func (s *Server) loginCallback(w http.ResponseWriter, r *http.Request) {
	id, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	p := s.pending(id)
	if p == nil || code == "" {
		loginResult(w, http.StatusBadRequest, "This login link has expired", "Run publiclocal login again.")
		return
	}
	cookie, err := r.Cookie(loginCookie)
	s.mu.RLock()
	bound := p.confirmed && err == nil && secretMatches(cookie.Value, p.browser)
	s.mu.RUnlock()
	if !bound {
		loginResult(w, http.StatusForbidden, "This sign-in did not start in this browser", "Open the login page from your own terminal's publiclocal login and enter the code there.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: loginCookie, Value: "", Path: "/", MaxAge: -1})

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	user, err := s.githubUser(ctx, code)
	if err != nil {
		s.log.Warn("github login failed", "err", err)
		loginResult(w, http.StatusBadGateway, "GitHub sign-in failed", "Please try publiclocal login again.")
		return
	}
	if age := s.cfg.MinGitHubAccountAge; age > 0 && time.Since(user.CreatedAt) < age {
		s.mu.Lock()
		p.err = fmt.Sprintf("GitHub accounts must be at least %d days old to sign in", int(age.Hours()/24))
		s.mu.Unlock()
		loginResult(w, http.StatusForbidden, "Your GitHub account is too new", p.err+". You can still use PublicLocal without signing in.")
		return
	}

	token := "plt_" + newSecret()
	s.mu.Lock()
	acct := s.accounts[user.Login]
	if acct == nil {
		acct = &account{Login: user.Login, GitHubID: user.ID, Created: time.Now()}
		s.accounts[user.Login] = acct
	}
	if acct.Banned {
		p.err = "this account is suspended"
		s.mu.Unlock()
		loginResult(w, http.StatusForbidden, "This account is suspended", "Contact abuse@"+s.cfg.Domain+" if you think this is a mistake.")
		return
	}
	acct.TokenHash = hashSecret(token) // one active login per account; signing in again replaces it
	acct.TokenCreated = time.Now()
	p.token, p.login = token, user.Login
	s.saveLocked()
	s.mu.Unlock()
	s.log.Info("account signed in", "login", user.Login)
	loginResult(w, http.StatusOK, "Signed in as "+user.Login, "You can close this tab and go back to your terminal.")
}

func (s *Server) loginPoll(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, Secret string }
	if r.Method != http.MethodPost || json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
		apiError(w, http.StatusBadRequest, "POST {id, secret}")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.logins[in.ID]
	if p == nil || !secretMatches(in.Secret, p.secretHash) || time.Since(p.created) > loginTTL {
		apiError(w, http.StatusNotFound, "login expired; run publiclocal login again")
		return
	}
	switch {
	case p.err != "":
		delete(s.logins, in.ID)
		apiError(w, http.StatusForbidden, p.err)
	case p.token == "":
		writeJSON(w, map[string]string{"status": "pending"})
	default:
		delete(s.logins, in.ID) // the token is handed out once
		writeJSON(w, map[string]string{"status": "ok", "token": p.token, "login": p.login})
	}
}

// accountByToken returns the GitHub login for an account token.
func (s *Server) accountByToken(token string) (string, error) {
	h := hashSecret(token)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.accounts {
		if a.TokenHash != "" && subtle.ConstantTimeCompare([]byte(h), []byte(a.TokenHash)) == 1 {
			switch {
			case a.Banned:
				return "", errors.New("this account is suspended")
			case !a.TokenCreated.IsZero() && time.Since(a.TokenCreated) > tokenMaxAge:
				return "", errors.New("your login has expired; run publiclocal login again")
			}
			return a.Login, nil
		}
	}
	return "", errors.New("your login has expired; run publiclocal login again")
}

func (s *Server) bearer(w http.ResponseWriter, r *http.Request) (string, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		apiError(w, http.StatusUnauthorized, "not signed in; run publiclocal login")
		return "", false
	}
	login, err := s.accountByToken(tok)
	if err != nil {
		apiError(w, http.StatusUnauthorized, err.Error())
		return "", false
	}
	return login, true
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	login, ok := s.bearer(w, r)
	if !ok {
		return
	}
	type link struct {
		URL     string    `json:"url"`
		Expires time.Time `json:"expires,omitzero"`
		Online  bool      `json:"online"`
	}
	out := struct {
		Login string `json:"login"`
		Links []link `json:"links"`
	}{Login: login, Links: []link{}}
	s.mu.RLock()
	for sub, res := range s.reservations {
		if res.Account == login {
			out.Links = append(out.Links, link{URL: s.httpURL(sub), Expires: res.Expires, Online: s.hosts[sub] != nil})
		}
	}
	s.mu.RUnlock()
	writeJSON(w, out)
}

// extend pushes a link's expiry to AccountTunnelAge from now. Only the
// signed-in owner can extend, and only links that haven't expired yet.
func (s *Server) extend(w http.ResponseWriter, r *http.Request) {
	login, ok := s.bearer(w, r)
	if !ok {
		return
	}
	var in struct{ Name string }
	if r.Method != http.MethodPost || json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
		apiError(w, http.StatusBadRequest, "POST {name}")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res := s.reservations[strings.ToLower(in.Name)]
	switch {
	case res == nil || res.expired(time.Now()):
		apiError(w, http.StatusNotFound, "no such link, or it has already expired")
		return
	case res.Account != login:
		apiError(w, http.StatusForbidden, "this link belongs to another user, or was created before you signed in")
		return
	case s.cfg.AccountTunnelAge <= 0 || res.Expires.IsZero():
		writeJSON(w, map[string]any{"url": s.httpURL(res.Sub), "expires": nil})
		return
	}
	res.Expires = time.Now().Add(s.cfg.AccountTunnelAge)
	s.scheduleExpiry(res)
	s.saveLocked()
	s.log.Info("link extended", "sub", res.Sub, "login", login, "expires", res.Expires)
	writeJSON(w, map[string]any{"url": s.httpURL(res.Sub), "expires": res.Expires})
}

// logout revokes the account token so a copied token stops working.
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	login, ok := s.bearer(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	if a := s.accounts[login]; a != nil {
		a.TokenHash = ""
		s.saveLocked()
	}
	s.mu.Unlock()
	writeJSON(w, map[string]bool{"ok": true})
}

type githubUser struct {
	Login     string    `json:"login"`
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// githubUser exchanges an OAuth code for the signed-in GitHub user. No scopes
// are requested: only public profile information is read, and the GitHub
// access token is discarded afterwards.
func (s *Server) githubUser(ctx context.Context, code string) (*githubUser, error) {
	token, err := s.githubToken(ctx, code)
	if err != nil {
		return nil, err
	}
	return s.githubUserFor(ctx, token)
}

// githubToken exchanges an OAuth code for an access token.
func (s *Server) githubToken(ctx context.Context, code string) (string, error) {
	form := url.Values{
		"client_id":     {s.cfg.GitHubClientID},
		"client_secret": {s.cfg.GitHubClientSecret},
		"code":          {code},
		"redirect_uri":  {s.baseURL() + "/auth/callback"},
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", s.cfg.GitHubURL+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error_description"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&tok)
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("no access token: %s", tok.Error)
	}
	return tok.AccessToken, nil
}

// githubUserFor reads the user a token belongs to. The token is not kept.
func (s *Server) githubUserFor(ctx context.Context, token string) (*githubUser, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", s.cfg.GitHubAPIURL+"/user", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github /user: %s", resp.Status)
	}
	var u githubUser
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&u); err != nil {
		return nil, err
	}
	if u.Login == "" {
		return nil, errors.New("github returned no login")
	}
	return &u, nil
}

// githubIsMember checks, with the user's own token, whether they belong to
// an organisation (private memberships need the read:org scope).
func (s *Server) githubIsMember(ctx context.Context, token, org, login string) bool {
	req, _ := http.NewRequestWithContext(ctx, "GET", s.cfg.GitHubAPIURL+"/orgs/"+url.PathEscape(org)+"/members/"+url.PathEscape(login), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusNoContent
}

var confirmTmpl = template.Must(template.New("confirm").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Sign in · PublicLocal</title><link rel="stylesheet" href="/style.css"></head>
<body><main class="wrap prose" style="padding:64px 16px">
<h1>Sign in to PublicLocal</h1>
<p>Enter the code shown in your terminal by <code>publiclocal login</code>:</p>
{{if .Error}}<p style="color:#c0392b"><strong>That code is not right.</strong> Check your terminal and try again.</p>{{end}}
<form method="post" action="/login">
<input type="hidden" name="id" value="{{.ID}}">
<input name="code" autocomplete="one-time-code" autofocus required placeholder="XXXX-XXXX" class="mono"
  style="font-size:26px;letter-spacing:.12em;text-transform:uppercase;padding:10px 14px;width:100%;max-width:320px;border:1px solid var(--line);border-radius:10px;background:var(--surface);color:var(--fg)">
<p><button class="btn primary" type="submit" style="border:0;cursor:pointer">Continue with GitHub</button></p>
</form>
<p style="color:var(--muted);font-size:15px">If you did not run <code>publiclocal login</code> yourself, close this page. Never enter a code someone else sent you.<br>
Signing in gives your links 7 days instead of 24 hours, and lets you extend them. PublicLocal only reads your public GitHub profile.</p>
</main></body></html>
`))

var resultTmpl = template.Must(template.New("result").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{{.Title}} · PublicLocal</title><link rel="stylesheet" href="/style.css"></head>
<body><main class="wrap prose" style="padding:64px 16px"><h1>{{.Title}}</h1><p>{{.Body}}</p><p><a href="/">PublicLocal home</a></p></main></body></html>
`))

func loginResult(w http.ResponseWriter, code int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	resultTmpl.Execute(w, struct{ Title, Body string }{title, body})
}
