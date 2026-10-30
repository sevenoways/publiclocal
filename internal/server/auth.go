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

// Login works like a device login: the CLI asks for a login, opens the
// returned URL in the browser, and polls until the user has signed in with
// GitHub there. The CLI then holds an account token it sends in its Hello.
//
//	POST /api/login/start   -> {id, secret, url}
//	GET  /login?id=ID       -> redirects to GitHub
//	GET  /auth/callback     <- GitHub redirects back here
//	POST /api/login/poll    {id, secret} -> {token, login} once signed in
//	GET  /api/me            Authorization: Bearer TOKEN -> {login}
//	POST /api/extend        Authorization: Bearer TOKEN, {name} -> {expires}

type pendingLogin struct {
	code       string // shown in the terminal and the browser, so the user can tell it's their login
	secretHash string
	created    time.Time
	token      string // set once the user has signed in
	login      string
	err        string
}

const loginTTL = 10 * time.Minute

func (s *Server) loginEnabled() bool { return s.cfg.GitHubClientID != "" }

// serveAccountAPI handles the login and account endpoints on the bare domain.
// It reports whether it handled the request.
func (s *Server) serveAccountAPI(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/api/login/start", "/api/login/poll", "/login", "/auth/callback", "/api/me", "/api/extend":
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
		s.loginRedirect(w, r)
	case "/auth/callback":
		s.loginCallback(w, r)
	case "/api/me":
		s.me(w, r)
	case "/api/extend":
		s.extend(w, r)
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
	id, secret := newSecret()[:16], newSecret()
	s.mu.Lock()
	now := time.Now()
	for k, p := range s.logins {
		if now.Sub(p.created) > loginTTL {
			delete(s.logins, k)
		}
	}
	if len(s.logins) > 10000 {
		s.mu.Unlock()
		apiError(w, http.StatusServiceUnavailable, "too many logins in progress, try again shortly")
		return
	}
	code := strings.ToUpper(randomName(4, 4) + "-" + randomName(4, 4))
	s.logins[id] = &pendingLogin{code: code, secretHash: hashSecret(secret), created: now}
	s.mu.Unlock()
	writeJSON(w, map[string]string{"id": id, "secret": secret, "code": code, "url": s.baseURL() + "/login?id=" + id})
}

func (s *Server) loginRedirect(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	s.mu.RLock()
	p := s.logins[id]
	s.mu.RUnlock()
	if p == nil || time.Since(p.created) > loginTTL {
		loginPage(w, http.StatusBadRequest, "This login link has expired", "Run publiclocal login again.")
		return
	}
	// Ask the user to compare codes first, so a login link someone else sent
	// can't be used to sign them in to the sender's terminal.
	if r.URL.Query().Get("confirm") != "1" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		confirmTmpl.Execute(w, struct{ ID, Code string }{id, p.code})
		return
	}
	q := url.Values{
		"client_id":    {s.cfg.GitHubClientID},
		"redirect_uri": {s.baseURL() + "/auth/callback"},
		"state":        {id},
		"allow_signup": {"false"},
	}
	http.Redirect(w, r, s.cfg.GitHubURL+"/login/oauth/authorize?"+q.Encode(), http.StatusFound)
}

func (s *Server) loginCallback(w http.ResponseWriter, r *http.Request) {
	id, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	s.mu.RLock()
	p := s.logins[id]
	s.mu.RUnlock()
	if p == nil || code == "" || time.Since(p.created) > loginTTL {
		loginPage(w, http.StatusBadRequest, "This login link has expired", "Run publiclocal login again.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	user, err := s.githubUser(ctx, code)
	if err != nil {
		s.log.Warn("github login failed", "err", err)
		loginPage(w, http.StatusBadGateway, "GitHub sign-in failed", "Please try publiclocal login again.")
		return
	}
	if age := s.cfg.MinGitHubAccountAge; age > 0 && time.Since(user.CreatedAt) < age {
		s.mu.Lock()
		p.err = fmt.Sprintf("GitHub accounts must be at least %d days old to sign in", int(age.Hours()/24))
		s.mu.Unlock()
		loginPage(w, http.StatusForbidden, "Your GitHub account is too new", p.err+". You can still use PublicLocal without signing in.")
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
		loginPage(w, http.StatusForbidden, "This account is suspended", "Contact abuse@"+s.cfg.Domain+" if you think this is a mistake.")
		return
	}
	acct.TokenHash = hashSecret(token) // one active login per account; signing in again replaces it
	p.token, p.login = token, user.Login
	s.saveLocked()
	s.mu.Unlock()
	s.log.Info("account signed in", "login", user.Login)
	loginPage(w, http.StatusOK, "Signed in as "+user.Login, "You can close this tab and go back to your terminal.")
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
			if a.Banned {
				return "", errors.New("this account is suspended")
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

type githubUser struct {
	Login     string    `json:"login"`
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// githubUser exchanges an OAuth code for the signed-in GitHub user. No scopes
// are requested: only public profile information is read, and the GitHub
// access token is discarded afterwards.
func (s *Server) githubUser(ctx context.Context, code string) (*githubUser, error) {
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
		return nil, err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error_description"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&tok)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("no access token: %s", tok.Error)
	}

	req, _ = http.NewRequestWithContext(ctx, "GET", s.cfg.GitHubAPIURL+"/user", nil)
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err = http.DefaultClient.Do(req)
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

var loginTmpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} · PublicLocal</title><link rel="stylesheet" href="/style.css"></head>
<body><main class="wrap prose" style="padding:64px 16px"><h1>{{.Title}}</h1><p>{{.Body}}</p><p><a href="/">PublicLocal home</a></p></main></body></html>
`))

var confirmTmpl = template.Must(template.New("confirm").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · PublicLocal</title><link rel="stylesheet" href="/style.css"></head>
<body><main class="wrap prose" style="padding:64px 16px">
<h1>Sign in to PublicLocal</h1>
<p>Check that this code matches the one in your terminal:</p>
<p class="mono" style="font-size:32px;font-weight:700;letter-spacing:.08em">{{.Code}}</p>
<p>If it doesn't match, or you didn't run <code>publiclocal login</code> yourself, close this page.</p>
<p><a class="btn primary" href="/login?id={{.ID}}&amp;confirm=1">Continue with GitHub</a></p>
<p style="color:var(--muted);font-size:15px">Signing in gives your links 7 days instead of 24 hours, and lets you extend them. PublicLocal only reads your public GitHub profile.</p>
</main></body></html>
`))

func loginPage(w http.ResponseWriter, code int, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	loginTmpl.Execute(w, struct{ Title, Body string }{title, body})
}
