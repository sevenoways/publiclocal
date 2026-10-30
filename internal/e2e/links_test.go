package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/proto"
	"github.com/sevenoways/publiclocal/internal/server"
)

// clientWatch runs a client and returns every TunnelInfo batch it reports.
func clientWatch(t *testing.T, cfg client.Config) <-chan []proto.TunnelInfo {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := make(chan []proto.TunnelInfo, 8)
	cfg.Logger = slog.New(slog.DiscardHandler)
	cfg.OnReady = func(i []proto.TunnelInfo) { ch <- i }
	go client.Run(ctx, cfg)
	return ch
}

func next(t *testing.T, ch <-chan []proto.TunnelInfo, within time.Duration) []proto.TunnelInfo {
	t.Helper()
	select {
	case i := <-ch:
		return i
	case <-time.After(within):
		t.Fatal("no tunnel reported in time")
		return nil
	}
}

var nameRE = regexp.MustCompile(`^[bcdfghjkmnpqrstvwxz2-9]{6,8}$`)

func TestReconnectKeepsLinkAndNames(t *testing.T) {
	srv, ctl, _ := startPublic(t, server.Config{MaxSessionsPerIP: 100})
	ch := clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}})
	first := next(t, ch, 5*time.Second)[0]

	if !nameRE.MatchString(first.Name) {
		t.Fatalf("name %q is not 6-8 chars from the safe alphabet", first.Name)
	}
	if d := time.Until(first.Expires); d < 23*time.Hour || d > 24*time.Hour {
		t.Fatalf("anonymous link should last 24h, expires in %v", d)
	}

	srv.Kill("", "127.0.0.1") // drop the connection; the client reconnects on its own
	second := next(t, ch, 10*time.Second)[0]
	if second.URL != first.URL || !second.Expires.Equal(first.Expires) {
		t.Fatalf("reconnect changed the link: %s (%v) -> %s (%v)", first.URL, first.Expires, second.URL, second.Expires)
	}

}

func TestLinksSurviveRestart(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	srv1, ctl1, _ := startPublic(t, server.Config{StateFile: state})

	// The client talks to a forwarder, so we can swap the server behind it.
	fwd := newForwarder(t, ctl1)
	ch := clientWatch(t, client.Config{Server: fwd.addr, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}})
	first := next(t, ch, 5*time.Second)[0]

	// "Restart": a new server process reading the same state file.
	_, ctl2, httpURL2 := startPublic(t, server.Config{StateFile: state})
	fwd.switchTo(ctl2)
	srv1.Kill("", "127.0.0.1")
	second := next(t, ch, 10*time.Second)[0]
	if second.URL != first.URL {
		t.Fatalf("link changed across restart: %s -> %s", first.URL, second.URL)
	}
	req, _ := http.NewRequest("GET", httpURL2, nil)
	req.Host = strings.TrimPrefix(second.URL, "http://")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("link not served after restart: %v %v", resp, err)
	}
	resp.Body.Close()

	// A different client never gets that name.
	other := next(t, clientWatch(t, client.Config{Server: ctl2, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}}), 5*time.Second)[0]
	if other.Name == first.Name {
		t.Fatal("a new client got someone else's link")
	}
}

// forwarder is a TCP relay whose target can change, standing in for a
// server restart behind the same address.
type forwarder struct {
	addr   string
	mu     sync.Mutex
	target string
}

func newForwarder(t *testing.T, target string) *forwarder {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &forwarder{addr: ln.Addr().String(), target: target}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			target := f.target
			f.mu.Unlock()
			go func() {
				b, err := net.Dial("tcp", target)
				if err != nil {
					c.Close()
					return
				}
				go func() { io.Copy(b, c); b.Close() }()
				io.Copy(c, b)
				c.Close()
			}()
		}
	}()
	return f
}

func (f *forwarder) switchTo(target string) {
	f.mu.Lock()
	f.target = target
	f.mu.Unlock()
}

// fakeGitHub answers the two GitHub endpoints the login flow uses.
func fakeGitHub(t *testing.T, login string, created time.Time) *httptest.Server {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			if r.FormValue("code") != "good-code" || r.FormValue("client_secret") != "secret" {
				json.NewEncoder(w).Encode(map[string]string{"error_description": "bad code"})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"access_token": "gh-token"})
		case "/user":
			if r.Header.Get("Authorization") != "Bearer gh-token" {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"login": login, "id": 42, "created_at": created})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(gh.Close)
	return gh
}

type apiResult struct {
	Status, Token, Login, Error, ID, Secret, Code, URL string
	Expires                                            time.Time
}

func api(t *testing.T, httpURL, method, path, token string, body any) (int, apiResult) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, httpURL+path, rd)
	req.Host = domain
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out apiResult
	b, _ := io.ReadAll(resp.Body)
	json.Unmarshal(b, &out)
	if resp.StatusCode == http.StatusFound {
		out.URL = resp.Header.Get("Location")
	}
	return resp.StatusCode, out
}

// login runs the whole browser flow against the fake GitHub and returns the token.
func login(t *testing.T, httpURL string) (string, apiResult) {
	t.Helper()
	_, start := api(t, httpURL, "POST", "/api/login/start", "", nil)
	if start.ID == "" || start.Code == "" {
		t.Fatalf("login start: %+v", start)
	}
	if code, page := api(t, httpURL, "GET", "/login?id="+start.ID, "", nil); code != 200 {
		t.Fatalf("confirm page: %d %+v", code, page)
	}
	code, redirect := api(t, httpURL, "GET", "/login?id="+start.ID+"&confirm=1", "", nil)
	if code != http.StatusFound || !strings.Contains(redirect.URL, "/login/oauth/authorize") {
		t.Fatalf("expected redirect to GitHub, got %d %q", code, redirect.URL)
	}
	if _, pending := api(t, httpURL, "POST", "/api/login/poll", "", map[string]string{"id": start.ID, "secret": start.Secret}); pending.Status != "pending" {
		t.Fatalf("poll before sign-in: %+v", pending)
	}
	api(t, httpURL, "GET", "/auth/callback?state="+start.ID+"&code=good-code", "", nil)
	_, done := api(t, httpURL, "POST", "/api/login/poll", "", map[string]string{"id": start.ID, "secret": start.Secret})
	return done.Token, done
}

func TestLoginGivesSevenDaysAndExtend(t *testing.T) {
	gh := fakeGitHub(t, "octocat", time.Now().AddDate(-3, 0, 0))
	_, ctl, httpURL := startPublic(t, server.Config{MaxSessionsPerIP: 100, GitHubClientID: "id", GitHubClientSecret: "secret", GitHubURL: gh.URL, GitHubAPIURL: gh.URL})

	token, done := login(t, httpURL)
	if token == "" || done.Login != "octocat" {
		t.Fatalf("login: %+v", done)
	}
	if _, again := api(t, httpURL, "POST", "/api/login/poll", "", map[string]string{"id": "x", "secret": "y"}); again.Error == "" {
		t.Fatal("poll with a wrong id should fail")
	}

	ch := clientWatch(t, client.Config{Server: ctl, Account: token, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}})
	link := next(t, ch, 5*time.Second)[0]
	if d := time.Until(link.Expires); d < 6*24*time.Hour {
		t.Fatalf("signed-in link should last 7 days, expires in %v", d)
	}

	// Extending pushes the expiry to 7 days from now.
	code, ext := api(t, httpURL, "POST", "/api/extend", token, map[string]string{"name": link.Name})
	if code != 200 || !ext.Expires.After(link.Expires.Add(-time.Second)) {
		t.Fatalf("extend: %d %+v", code, ext)
	}
	// Strangers and anonymous callers can't extend it.
	if code, _ := api(t, httpURL, "POST", "/api/extend", "", map[string]string{"name": link.Name}); code != 401 {
		t.Fatalf("anonymous extend: %d", code)
	}
	if code, _ := api(t, httpURL, "POST", "/api/extend", "plt_bogus", map[string]string{"name": link.Name}); code != 401 {
		t.Fatalf("bogus token extend: %d", code)
	}

	// An anonymous link can't be extended even by a signed-in user.
	anon := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}}), 5*time.Second)[0]
	if code, _ := api(t, httpURL, "POST", "/api/extend", token, map[string]string{"name": anon.Name}); code != 403 {
		t.Fatalf("extending someone else's link: %d", code)
	}

	// A bad login token is refused at connect time with a clear message.
	err := runQuiet(client.Config{Server: ctl, Account: "plt_bogus", Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1"}}})
	if !rejected(err) || !strings.Contains(err.Error(), "login") {
		t.Fatalf("bogus account: %v", err)
	}
}

func TestNewGitHubAccountsCannotLogIn(t *testing.T) {
	gh := fakeGitHub(t, "brandnew", time.Now().AddDate(0, 0, -3))
	_, _, httpURL := startPublic(t, server.Config{MaxSessionsPerIP: 100, GitHubClientID: "id", GitHubClientSecret: "secret", GitHubURL: gh.URL, GitHubAPIURL: gh.URL})
	token, done := login(t, httpURL)
	if token != "" || !strings.Contains(done.Error, "days old") {
		t.Fatalf("new account should be refused: %+v", done)
	}
}

func TestMisuseCheckerAndSuspend(t *testing.T) {
	srv, ctl, _ := startPublic(t, server.Config{MaxSessionsPerIP: 100})
	phish := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><title>PayPal - Log in</title><form><input name=email><input type="password" name=pw></form></html>`)
	}))
	defer phish.Close()
	ok := webApp(t)

	bad := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: phish.Listener.Addr().String()}}}), 5*time.Second)[0]
	next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: ok}}}), 5*time.Second)

	flags := srv.ScanNow()
	if len(flags) != 1 || flags[0].URL != bad.URL || !strings.Contains(flags[0].Reason, "paypal") {
		t.Fatalf("expected one flag for %s, got %+v", bad.URL, flags)
	}

	if ip, _, found := srv.Suspend(bad.Name); !found || ip != "127.0.0.1" {
		t.Fatalf("suspend: %q %v", ip, found)
	}
	err := runQuiet(client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: ok}}})
	if !rejected(err) || !strings.Contains(err.Error(), "banned") {
		t.Fatalf("suspended IP should be banned, got %v", err)
	}
}
