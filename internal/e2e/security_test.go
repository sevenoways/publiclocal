package e2e

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/proto"
	"github.com/sevenoways/publiclocal/internal/server"
)

// These tests cover ways a hostile tunnel owner or visitor could get around
// the safeguards of a public server.

type tunnelReq struct {
	t       *testing.T
	httpURL string
	host    string
}

func (q tunnelReq) do(method, path string, hdr map[string]string, body string) (*http.Response, string) {
	q.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, q.httpURL+path, rd)
	req.Host = q.host
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		q.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

var browserHdr = map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "text/html", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}

func TestWarningCannotBeBypassed(t *testing.T) {
	_, ctl, httpURL := startPublic(t, server.Config{})
	// A hostile app that tries to switch the warning off for its visitors.
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "publiclocal_warning_ok=1; Path=/")
		w.Header().Add("Set-Cookie", "publiclocal_warning_ok=1; Path=/; Domain=tunnel.test")
		w.Header().Add("Set-Cookie", "session=abc; Path=/")
		w.Header().Add("Set-Cookie", "tracker=x; Domain=.tunnel.test; Path=/")
		fmt.Fprint(w, "PHISH")
	}))
	defer evil.Close()
	info := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: evil.Listener.Addr().String()}}}), 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	q := tunnelReq{t, httpURL, u.Host}
	continueHdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}

	// 1. Cross-site form POST to the continue endpoint is refused.
	for _, hdr := range []map[string]string{
		{"Origin": "https://attacker.example"},
		{"Sec-Fetch-Site": "cross-site", "Origin": "http://" + u.Host},
		{}, // no browser headers at all
	} {
		for k, v := range continueHdr {
			hdr[k] = v
		}
		resp, _ := q.do("POST", "/.publiclocal/continue", hdr, "next=/")
		if resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
			t.Fatalf("cross-site continue with %v: %d cookies=%d", hdr, resp.StatusCode, len(resp.Cookies()))
		}
	}
	// Same-origin works and the cookie is signed, not "1".
	resp, _ := q.do("POST", "/.publiclocal/continue", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "http://" + u.Host}, "next=/x")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/x" || len(resp.Cookies()) != 1 || resp.Cookies()[0].Value == "1" {
		t.Fatalf("same-origin continue: %d %v", resp.StatusCode, resp.Cookies())
	}
	good := resp.Cookies()[0]

	// 2. A forged cookie does not count; a signed one for another host does not either.
	if _, body := q.do("GET", "/", with(browserHdr, "Cookie", "publiclocal_warning_ok=1"), ""); !strings.Contains(body, "temporary developer link") {
		t.Fatal("forged cookie skipped the warning")
	}
	other := tunnelReq{t, httpURL, "zzzzzz." + domain}
	if resp, _ := other.do("GET", "/", with(browserHdr, "Cookie", good.Name+"="+good.Value), ""); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("unexpected status for other host: %d", resp.StatusCode)
	}
	if _, body := q.do("GET", "/", with(browserHdr, "Cookie", good.Name+"="+good.Value), ""); body != "PHISH" {
		t.Fatalf("signed cookie should reach the app, got %q", body)
	}

	// 3. Non-GET navigations are gated too.
	if _, body := q.do("POST", "/submit", with(browserHdr, "Content-Type", "application/x-www-form-urlencoded"), "a=b"); !strings.Contains(body, "temporary developer link") {
		t.Fatal("POST navigation skipped the warning")
	}
	// Non-navigation requests (images, fetch, curl) pass straight through.
	if _, body := q.do("GET", "/pixel.png", map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "image/*", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"}, ""); body != "PHISH" {
		t.Fatalf("image request should reach the app, got %q", body)
	}

	// 4. The app's Set-Cookie attempts for our cookie, or for the whole domain, are stripped.
	resp, _ = q.do("GET", "/pixel.png", map[string]string{"Accept": "image/*"}, "")
	var names []string
	for _, c := range resp.Cookies() {
		names = append(names, c.Name+"@"+c.Domain)
	}
	if strings.Join(names, ",") != "session@" {
		t.Fatalf("cookies passed through: %v", names)
	}

	// 5. The open-redirect tricks on next are neutralised.
	for _, bad := range []string{"//evil.example", "/\\evil.example", "https://evil.example", "/\t\\evil.example"} {
		resp, _ := q.do("POST", "/.publiclocal/continue", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "http://" + u.Host}, "next="+url.QueryEscape(bad))
		if loc := resp.Header.Get("Location"); loc != "/" {
			t.Fatalf("next=%q redirected to %q", bad, loc)
		}
	}

	// 6. No certificates for tunnel names.
	if resp, _ := q.do("GET", "/.well-known/acme-challenge/token", nil, ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("acme challenge proxied: %d", resp.StatusCode)
	}
}

func with(h map[string]string, k, v string) map[string]string {
	out := map[string]string{k: v}
	for kk, vv := range h {
		out[kk] = vv
	}
	return out
}

func TestLinkCapsAndConnectRate(t *testing.T) {
	srv, ctl, _ := startPublic(t, server.Config{MaxSessionsPerIP: 100, MaxLinksPerIP: 3})
	_ = srv
	for range 3 {
		next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1"}}}), 5*time.Second)
	}
	err := runQuiet(client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1"}}})
	if !rejected(err) || !strings.Contains(err.Error(), "too many active links") {
		t.Fatalf("4th link from one IP should be refused, got %v", err)
	}

	// Connection rate limit: the 3rd connection in a minute is dropped.
	_, ctl2, _ := startPublic(t, server.Config{MaxSessionsPerIP: 100, ConnectsPerMinute: 2})
	for i := range 3 {
		c, err := net.Dial("tcp", ctl2)
		if err != nil {
			t.Fatal(err)
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Read(make([]byte, 1))
		c.Close()
		closed := err != nil && !strings.Contains(err.Error(), "timeout")
		if i < 2 && closed {
			t.Fatalf("connection %d should be accepted: %v", i+1, err)
		}
		if i == 2 && !closed {
			t.Fatal("3rd connection in a minute should be closed")
		}
	}
}

func TestOwnerReclaimsLinkByName(t *testing.T) {
	gh := fakeGitHub(t, "octocat", time.Now().AddDate(-3, 0, 0))
	_, ctl, httpURL := startPublic(t, server.Config{MaxSessionsPerIP: 100, GitHubClientID: "id", GitHubClientSecret: "secret", GitHubURL: gh.URL, GitHubAPIURL: gh.URL})
	token, _ := login(t, httpURL)

	first := next(t, clientWatch(t, client.Config{Server: ctl, Account: token, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}}), 5*time.Second)[0]

	// After a restart (no claim), the owner asks for the link by name and gets it back.
	again := next(t, clientWatch(t, client.Config{Server: ctl, Account: token, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t), Subdomain: first.Name}}}), 5*time.Second)[0]
	if again.URL != first.URL || again.Claim == "" {
		t.Fatalf("owner reclaim: %+v", again)
	}
	// Someone else, signed in or not, cannot.
	if err := runQuiet(client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1", Subdomain: first.Name}}}); !rejected(err) {
		t.Fatalf("stranger reclaim: %v", err)
	}
	gh2 := fakeGitHub(t, "mallory", time.Now().AddDate(-3, 0, 0))
	_ = gh2
	// Logout revokes the token.
	if code, _ := api(t, httpURL, "POST", "/api/logout", token, nil); code != 200 {
		t.Fatalf("logout: %d", code)
	}
	if code, _ := api(t, httpURL, "GET", "/api/me", token, nil); code != 401 {
		t.Fatalf("token still valid after logout: %d", code)
	}
}

func TestLoginLinkCannotBeUsedWithoutCode(t *testing.T) {
	gh := fakeGitHub(t, "victim", time.Now().AddDate(-3, 0, 0))
	_, _, httpURL := startPublic(t, server.Config{GitHubClientID: "id", GitHubClientSecret: "secret", GitHubURL: gh.URL, GitHubAPIURL: gh.URL})
	_, start := api(t, httpURL, "POST", "/api/login/start", "", nil)

	// The old shortcut is gone, and the callback refuses a browser that never typed the code.
	victim := browser(t, httpURL)
	if resp := victim("GET", "/login?id="+start.ID+"&confirm=1", nil); resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
		t.Fatalf("confirm shortcut: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp := victim("GET", "/auth/callback?state="+start.ID+"&code=good-code", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("callback without confirmation: %d", resp.StatusCode)
	}
	if _, poll := api(t, httpURL, "POST", "/api/login/poll", "", map[string]string{"id": start.ID, "secret": start.Secret}); poll.Status != "pending" {
		t.Fatalf("attacker got a token: %+v", poll)
	}

	// Even with the code typed in one browser, the callback must come from that browser.
	typed := browser(t, httpURL)
	typed("POST", "/login", url.Values{"id": {start.ID}, "code": {start.Code}})
	if resp := victim("GET", "/auth/callback?state="+start.ID+"&code=good-code", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("callback from another browser: %d", resp.StatusCode)
	}

	// Too many wrong codes burn the login.
	_, start2 := api(t, httpURL, "POST", "/api/login/start", "", nil)
	b := browser(t, httpURL)
	for range 6 {
		b("POST", "/login", url.Values{"id": {start2.ID}, "code": {"WRONG"}})
	}
	if resp := b("POST", "/login", url.Values{"id": {start2.ID}, "code": {start2.Code}}); resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("login should be burnt after wrong codes: %d", resp.StatusCode)
	}
}

func TestLoginStartRateLimited(t *testing.T) {
	gh := fakeGitHub(t, "x", time.Now().AddDate(-3, 0, 0))
	_, _, httpURL := startPublic(t, server.Config{LoginsPerMinute: 3, GitHubClientID: "id", GitHubClientSecret: "secret", GitHubURL: gh.URL, GitHubAPIURL: gh.URL})
	codes := []int{}
	for range 4 {
		code, _ := api(t, httpURL, "POST", "/api/login/start", "", nil)
		codes = append(codes, code)
	}
	if fmt.Sprint(codes) != "[200 200 200 429]" {
		t.Fatalf("rate limit: %v", codes)
	}
}

func TestSuspendTakesAllLinksOfTheAccount(t *testing.T) {
	gh := fakeGitHub(t, "spammer", time.Now().AddDate(-3, 0, 0))
	srv, ctl, httpURL := startPublic(t, server.Config{MaxSessionsPerIP: 100, GitHubClientID: "id", GitHubClientSecret: "secret", GitHubURL: gh.URL, GitHubAPIURL: gh.URL})
	token, _ := login(t, httpURL)
	a := next(t, clientWatch(t, client.Config{Server: ctl, Account: token, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}}), 5*time.Second)[0]
	b := next(t, clientWatch(t, client.Config{Server: ctl, Account: token, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}}), 5*time.Second)[0]

	srv.Suspend(a.Name)
	deadline := time.Now().Add(3 * time.Second)
	for len(srv.Tunnels()) != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(srv.Tunnels()); n != 0 {
		t.Fatalf("%d sessions still open after suspend", n)
	}
	q := tunnelReq{t, httpURL, strings.TrimPrefix(b.URL, "http://")}
	if resp, _ := q.do("GET", "/", nil, ""); resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("the account's other link still served: %d", resp.StatusCode)
	}
	if code, _ := api(t, httpURL, "GET", "/api/me", token, nil); code != 401 {
		t.Fatalf("suspended account token still works: %d", code)
	}
}

func TestAdminRefusesBrowsers(t *testing.T) {
	srv, _, _ := startPublic(t, server.Config{AdminToken: "sekrit"})
	admin := httptest.NewServer(srv.AdminHandler())
	defer admin.Close()
	get := func(hdr map[string]string) int {
		req, _ := http.NewRequest("GET", admin.URL+"/tunnels", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := get(map[string]string{"Origin": "http://evil.example", "Authorization": "Bearer sekrit"}); c != 403 {
		t.Fatalf("browser request: %d", c)
	}
	if c := get(nil); c != 401 {
		t.Fatalf("missing token: %d", c)
	}
	if c := get(map[string]string{"Authorization": "Bearer sekrit"}); c != 200 {
		t.Fatalf("with token: %d", c)
	}
}
