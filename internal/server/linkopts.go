package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/sevenoways/publiclocal/internal/proto"
)

// linkOpts are the per-link settings visitors run into. They sit behind an
// atomic pointer on the route, so SSH users can change them after the link
// exists (their options arrive with the shell command, after -R).
type linkOpts struct {
	password    string
	note        string
	maxVisit    int
	hostHeader  string
	allowNets   []netip.Prefix
	allowUsers  []string // lowercase GitHub logins
	allowOrgs   []string // lowercase GitHub organisations
	needsGitHub bool
}

var (
	githubNameRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,38})$`)
	hostHeaderRE = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$`)
)

const maxListEntries = 50

// parseLinkOpts validates the options a client asked for.
func (s *Server) parseLinkOpts(t proto.TunnelReq) (*linkOpts, error) {
	o := &linkOpts{password: t.Password, note: strings.TrimSpace(t.Note), maxVisit: t.MaxVisitors}
	if len(o.password) > 200 || len(o.note) > 200 {
		return nil, errors.New("password or note too long (200 characters)")
	}
	if o.maxVisit < 0 {
		return nil, errors.New("max-visits must be positive")
	}
	if h := t.HostHeader; h != "" {
		if !hostHeaderRE.MatchString(h) {
			return nil, fmt.Errorf("invalid host header %q", h)
		}
		o.hostHeader = h
	}
	if len(t.AllowIPs) > maxListEntries || len(t.AllowGitHub) > maxListEntries {
		return nil, fmt.Errorf("at most %d allowed addresses or GitHub names", maxListEntries)
	}
	for _, a := range t.AllowIPs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		p, err := netip.ParsePrefix(a)
		if err != nil {
			addr, err2 := netip.ParseAddr(a)
			if err2 != nil {
				return nil, fmt.Errorf("invalid address %q in allow-ip", a)
			}
			p = netip.PrefixFrom(addr, addr.BitLen())
		}
		o.allowNets = append(o.allowNets, p.Masked())
	}
	for _, g := range t.AllowGitHub {
		g = strings.ToLower(strings.TrimSpace(g))
		if g == "" {
			continue
		}
		org := strings.HasPrefix(g, "@")
		g = strings.TrimPrefix(g, "@")
		if !githubNameRE.MatchString(g) {
			return nil, fmt.Errorf("invalid GitHub name %q in allow-github", g)
		}
		if org {
			o.allowOrgs = append(o.allowOrgs, g)
		} else {
			o.allowUsers = append(o.allowUsers, g)
		}
	}
	o.needsGitHub = len(o.allowUsers)+len(o.allowOrgs) > 0
	if o.needsGitHub && !s.loginEnabled() {
		return nil, errors.New("allow-github needs GitHub sign-in, which this server does not offer")
	}
	return o, nil
}

// ipAllowed reports whether a visitor address passes the allowlist.
func (o *linkOpts) ipAllowed(remoteAddr string) bool {
	if len(o.allowNets) == 0 {
		return true
	}
	addr, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := addr.Addr().Unmap()
	for _, p := range o.allowNets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// SSH users pass options as `ssh … publiclocal.app password=s3cret expires=30m`.
// sshOptions turns those words into a TunnelReq.
func sshOptions(words []string) (proto.TunnelReq, time.Duration, error) {
	var t proto.TunnelReq
	var expires time.Duration
	for _, w := range words {
		k, v, ok := strings.Cut(w, "=")
		if !ok {
			return t, 0, fmt.Errorf("options look like name=value; got %q", w)
		}
		switch strings.ToLower(k) {
		case "password":
			t.Password = v
		case "note":
			t.Note = v
		case "max-visits", "visits":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return t, 0, fmt.Errorf("max-visits must be a number")
			}
			t.MaxVisitors = n
		case "expires":
			d, err := time.ParseDuration(v)
			if err != nil || d <= 0 {
				return t, 0, fmt.Errorf("expires must look like 30m or 2h")
			}
			expires = d
		case "host-header", "host":
			t.HostHeader = v
		case "allow-ip":
			t.AllowIPs = strings.Split(v, ",")
		case "allow-github":
			t.AllowGitHub = strings.Split(v, ",")
		default:
			return t, 0, fmt.Errorf("unknown option %q (try password, expires, max-visits, note, host-header, allow-ip, allow-github)", k)
		}
	}
	return t, expires, nil
}

// --- GitHub-gated links ---------------------------------------------------
//
// A gated link sends visitors to sign in with GitHub on the bare domain (the
// only redirect URL the OAuth app has). After GitHub, the bare domain hands a
// short-lived signed ticket back to the link's host, which turns it into a
// host-only cookie. Tickets and cookies are HMACs over the link's host, so
// one link's sign-in never opens another.

const (
	viewerCookie     = "publiclocal_viewer"
	viewerAuthPath   = "/.publiclocal/auth"
	viewerTTL        = 4 * time.Hour // also how long a removed org member keeps access
	ticketTTL        = 2 * time.Minute
	bindCookie       = "publiclocal_bind"
	maxVisitorsPerIP = 20
)

// viewerScope names one link instance: the host plus a random ID made with
// the route, so a sign-in for a link never carries over to whoever gets the
// same name later.
func viewerScope(host string, rt *route) string { return host + "#" + rt.id }

type viewer struct {
	login string
	orgs  []string // organisations whose membership was checked at sign-in
}

func (s *Server) signViewer(kind, host string, v viewer, exp time.Time) string {
	payload := strings.Join([]string{v.login, strings.Join(v.orgs, ","), strconv.FormatInt(exp.Unix(), 10)}, "|")
	m := hmac.New(sha256.New, s.cookieKey)
	m.Write([]byte(kind + ":" + host + ":" + payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + hex.EncodeToString(m.Sum(nil))
}

func (s *Server) verifyViewer(kind, host, token string) (viewer, bool) {
	b64, mac, ok := strings.Cut(token, ".")
	if !ok {
		return viewer{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return viewer{}, false
	}
	m := hmac.New(sha256.New, s.cookieKey)
	m.Write([]byte(kind + ":" + host + ":" + string(raw)))
	want := hex.EncodeToString(m.Sum(nil))
	if !hmac.Equal([]byte(mac), []byte(want)) {
		return viewer{}, false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return viewer{}, false
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return viewer{}, false
	}
	v := viewer{login: parts[0]}
	if parts[1] != "" {
		v.orgs = strings.Split(parts[1], ",")
	}
	return v, true
}

func (o *linkOpts) admits(v viewer) bool {
	if slices.Contains(o.allowUsers, v.login) {
		return true
	}
	for _, org := range v.orgs {
		if slices.Contains(o.allowOrgs, org) {
			return true
		}
	}
	return false
}

// githubGate lets a request through when the visitor is signed in and on the
// list. It reports whether the request may continue.
func (s *Server) githubGate(w http.ResponseWriter, r *http.Request, host, sub string, rt *route, o *linkOpts) bool {
	if c, err := r.Cookie(viewerCookie); err == nil {
		if v, ok := s.verifyViewer("viewer", viewerScope(host, rt), c.Value); ok && o.admits(v) {
			return true
		} else if ok {
			s.statusPage(w, r, statusPage{
				Code: http.StatusForbidden, Host: host,
				Title:   "This link is shared with specific GitHub users",
				Message: "You are signed in as " + v.login + ", who is not on this link's list.",
				Hint:    "Ask the person who shared it to add you.",
			})
			return false
		}
	}
	if !isNavigation(r) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "publiclocal: this link needs GitHub sign-in in a browser", http.StatusUnauthorized)
		return false
	}
	// Tie the coming ticket to this browser: a cookie on the link's host whose
	// hash travels through the sign-in and is part of the ticket's signature.
	nonce := newSecret()
	http.SetCookie(w, &http.Cookie{Name: bindCookie, Value: nonce, Path: viewerAuthPath, MaxAge: int(loginTTL.Seconds()), HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	q := url.Values{"link": {sub}, "next": {safeNext(r.URL.RequestURI())}, "bind": {hashSecret(nonce)}}
	http.Redirect(w, r, s.baseURL()+"/visitor-login?"+q.Encode(), http.StatusSeeOther)
	return false
}

// acceptViewerTicket turns a ticket from the bare domain into a viewer
// cookie. Tickets only work once, and only in the browser that started the
// sign-in.
func (s *Server) acceptViewerTicket(w http.ResponseWriter, r *http.Request, host string, rt *route) {
	t := r.URL.Query().Get("t")
	c, err := r.Cookie(bindCookie)
	if err != nil {
		http.Error(w, "publiclocal: sign-in did not start in this browser; open the link again", http.StatusForbidden)
		return
	}
	v, ok := s.verifyViewer("ticket", viewerScope(host, rt)+":"+hashSecret(c.Value), t)
	if !ok || !s.useTicket(t) {
		http.Error(w, "publiclocal: sign-in expired, open the link again", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: bindCookie, Value: "", Path: viewerAuthPath, MaxAge: -1})
	exp := time.Now().Add(viewerTTL)
	http.SetCookie(w, &http.Cookie{
		Name: viewerCookie, Value: s.signViewer("viewer", viewerScope(host, rt), v, exp), Path: "/",
		MaxAge: int(viewerTTL.Seconds()), HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
}

// useTicket records a ticket as spent and reports whether it was fresh.
func (s *Server) useTicket(t string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, exp := range s.spentTickets {
		if now.After(exp) {
			delete(s.spentTickets, k)
		}
	}
	if _, spent := s.spentTickets[t]; spent {
		return false
	}
	s.spentTickets[t] = now.Add(ticketTTL)
	return true
}

// stripCookie keeps one of our cookies from reaching the tunnelled app.
func stripCookie(r *http.Request, name string) {
	if !strings.Contains(r.Header.Get("Cookie"), name) {
		return
	}
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != name {
			r.AddCookie(c)
		}
	}
}

// pendingVisitor is a visitor on their way through GitHub sign-in.
type pendingVisitor struct {
	sub, next string
	bind      string // hash of the link-host cookie the ticket is bound to
	ipKey     string
	browser   string // hash of the cookie set on the bare domain before GitHub
	created   time.Time
}

const visitorCookie = "publiclocal_visit"

// visitorLogin starts GitHub sign-in for a gated link.
func (s *Server) visitorLogin(w http.ResponseWriter, r *http.Request) {
	if !s.loginLimit.allow(ipKey(r.RemoteAddr)) {
		http.Error(w, "too many sign-in attempts; try again in a minute", http.StatusTooManyRequests)
		return
	}
	sub := strings.ToLower(r.URL.Query().Get("link"))
	s.mu.RLock()
	rt := s.hosts[sub]
	s.mu.RUnlock()
	if rt == nil || !rt.opts.Load().needsGitHub {
		loginResult(w, http.StatusNotFound, "This link is not available", "It may have expired or no longer need sign-in.")
		return
	}
	bind := r.URL.Query().Get("bind")
	if len(bind) != 64 {
		loginResult(w, http.StatusBadRequest, "This sign-in link is incomplete", "Open the link again.")
		return
	}
	key := ipKey(r.RemoteAddr)
	id, nonce := "v"+newSecret()[:15], newSecret()
	s.mu.Lock()
	now := time.Now()
	mine := 0
	for k, p := range s.visitors {
		if now.Sub(p.created) > loginTTL {
			delete(s.visitors, k)
		} else if p.ipKey == key {
			mine++
		}
	}
	if len(s.visitors) >= maxPendingLogins || mine >= maxVisitorsPerIP {
		s.mu.Unlock()
		http.Error(w, "too many sign-ins in progress; try again shortly", http.StatusServiceUnavailable)
		return
	}
	s.visitors[id] = &pendingVisitor{sub: sub, next: safeNext(r.URL.Query().Get("next")), bind: bind, ipKey: key, browser: hashSecret(nonce), created: now}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: visitorCookie, Value: nonce, Path: "/", MaxAge: int(loginTTL.Seconds()), HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	q := url.Values{
		"client_id":    {s.cfg.GitHubClientID},
		"redirect_uri": {s.baseURL() + "/auth/callback"},
		"state":        {id},
		"allow_signup": {"true"},
	}
	if len(rt.opts.Load().allowOrgs) > 0 {
		q.Set("scope", "read:org") // to see private organisation membership
	}
	http.Redirect(w, r, s.cfg.GitHubURL+"/login/oauth/authorize?"+q.Encode(), http.StatusSeeOther)
}

// visitorCallback finishes a gated-link sign-in and hands a ticket to the link.
func (s *Server) visitorCallback(w http.ResponseWriter, r *http.Request, id, code string) {
	s.mu.Lock()
	p := s.visitors[id]
	delete(s.visitors, id)
	s.mu.Unlock()
	c, err := r.Cookie(visitorCookie)
	if p == nil || time.Since(p.created) > loginTTL || err != nil || !secretMatches(c.Value, p.browser) {
		loginResult(w, http.StatusForbidden, "This sign-in did not start in this browser", "Open the link again.")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: visitorCookie, Value: "", Path: "/", MaxAge: -1})
	s.mu.RLock()
	rt := s.hosts[p.sub]
	s.mu.RUnlock()
	if rt == nil {
		loginResult(w, http.StatusNotFound, "This link is not available", "It may have expired.")
		return
	}
	o := rt.opts.Load()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	token, err := s.githubToken(ctx, code)
	var user *githubUser
	if err == nil {
		user, err = s.githubUserFor(ctx, token)
	}
	if err != nil {
		s.log.Warn("visitor github sign-in failed", "err", err)
		loginResult(w, http.StatusBadGateway, "GitHub sign-in failed", "Open the link and try again.")
		return
	}
	v := viewer{login: strings.ToLower(user.Login)}
	for _, org := range o.allowOrgs {
		if s.githubIsMember(ctx, token, org, user.Login) {
			v.orgs = append(v.orgs, org)
		}
	}
	host := p.sub + "." + s.cfg.Domain
	ticket := s.signViewer("ticket", viewerScope(host, rt)+":"+p.bind, v, time.Now().Add(ticketTTL))
	q := url.Values{"t": {ticket}, "next": {p.next}}
	http.Redirect(w, r, s.httpURL(p.sub)+viewerAuthPath+"?"+q.Encode(), http.StatusSeeOther)
}
