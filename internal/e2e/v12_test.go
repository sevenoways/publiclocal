package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/proto"
	"github.com/sevenoways/publiclocal/internal/server"
)

func hostEcho(t *testing.T) string {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s fwd=%s", r.Host, r.Header.Get("X-Forwarded-Host"))
	}))
	t.Cleanup(app.Close)
	return app.Listener.Addr().String()
}

func TestHostHeaderAndAllowIP(t *testing.T) {
	_, ctl, httpURL := startPublic(t, server.Config{MaxSessionsPerIP: 100})
	info := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: hostEcho(t), HostHeader: "localhost:5173"}}}), 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	if _, body := (tunnelReq{t, httpURL, u.Host}).do("GET", "/", nil, ""); body != "host=localhost:5173 fwd="+u.Host {
		t.Fatalf("host header: %q", body)
	}

	// Only 10.0.0.0/8 may visit, so the test's 127.0.0.1 is turned away.
	info2 := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: hostEcho(t), AllowIPs: []string{"10.0.0.0/8"}}}}), 5*time.Second)[0]
	u2, _ := url.Parse(info2.URL)
	if resp, _ := (tunnelReq{t, httpURL, u2.Host}).do("GET", "/", nil, ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("allow-ip should refuse 127.0.0.1: %d", resp.StatusCode)
	}
	info3 := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: hostEcho(t), AllowIPs: []string{"127.0.0.1"}}}}), 5*time.Second)[0]
	u3, _ := url.Parse(info3.URL)
	if resp, _ := (tunnelReq{t, httpURL, u3.Host}).do("GET", "/", nil, ""); resp.StatusCode != 200 {
		t.Fatalf("allow-ip should admit 127.0.0.1: %d", resp.StatusCode)
	}
	// Bad options are refused at connect time.
	for _, bad := range []client.Tunnel{
		{Type: proto.TypeHTTP, Local: "127.0.0.1:1", HostHeader: "evil\r\nX: y"},
		{Type: proto.TypeHTTP, Local: "127.0.0.1:1", AllowIPs: []string{"not-an-ip"}},
		{Type: proto.TypeHTTP, Local: "127.0.0.1:1", AllowGitHub: []string{"octocat"}}, // no GitHub app on this server
	} {
		if err := runQuiet(client.Config{Server: ctl, Tunnels: []client.Tunnel{bad}}); !rejected(err) {
			t.Fatalf("option %+v should be refused, got %v", bad, err)
		}
	}
}

// fakeGitHubOrgs answers the OAuth exchange, /user, and org membership.
func fakeGitHubOrgs(t *testing.T, login string, orgs []string) *httptest.Server {
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login/oauth/access_token":
			json.NewEncoder(w).Encode(map[string]string{"access_token": "gh-token"})
		case r.URL.Path == "/user":
			json.NewEncoder(w).Encode(map[string]any{"login": login, "id": 7, "created_at": time.Now().AddDate(-2, 0, 0)})
		case strings.HasPrefix(r.URL.Path, "/orgs/"):
			for _, o := range orgs {
				if r.URL.Path == "/orgs/"+o+"/members/"+login {
					w.WriteHeader(http.StatusNoContent)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(gh.Close)
	return gh
}

// visit walks a browser through a gated link: link → bare-domain sign-in →
// (fake) GitHub → callback → ticket on the link host → the app.
func visit(t *testing.T, httpURL, linkHost string) (int, string) {
	code, body, _ := visitTicket(t, httpURL, linkHost)
	return code, body
}

// visitTicket is visit that also returns the ticket path it used.
func visitTicket(t *testing.T, httpURL, linkHost string) (int, string, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	hu, _ := url.Parse(httpURL)
	cl := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	skipWarning := false
	get := func(host, path string) *http.Response {
		req, _ := http.NewRequest("GET", httpURL+path, nil)
		req.Host = host
		for k, v := range browserHdr {
			req.Header.Set(k, v)
		}
		if skipWarning {
			// Signed-in viewers still see the warning page once; skip it here.
			req.Header.Set("PublicLocal-Skip-Warning", "1")
		}
		// The jar keys cookies by URL host; give it the virtual host instead.
		pu, _ := url.Parse(path)
		for _, c := range jar.Cookies(&url.URL{Scheme: "http", Host: host, Path: pu.Path}) {
			req.AddCookie(c)
		}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		jar.SetCookies(&url.URL{Scheme: "http", Host: host, Path: pu.Path}, resp.Cookies())
		return resp
	}
	resp := get(linkHost, "/secret?x=1")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || loc.Path != "/visitor-login" {
		t.Fatalf("gated link should send the browser to sign in: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp = get(domain, loc.RequestURI())
	gh, _ := url.Parse(resp.Header.Get("Location"))
	state := gh.Query().Get("state")
	if state == "" {
		t.Fatalf("no GitHub redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp = get(domain, "/auth/callback?state="+url.QueryEscape(state)+"&code=c")
	back, _ := url.Parse(resp.Header.Get("Location"))
	if back == nil || back.Path != "/.publiclocal/auth" {
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), ""
	}
	resp = get(linkHost, back.RequestURI())
	if resp.StatusCode != http.StatusSeeOther {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("ticket refused: %d %q", resp.StatusCode, b)
	}
	// Spent: the same ticket in the same browser no longer works.
	if again := get(linkHost, back.RequestURI()); again.StatusCode != http.StatusForbidden {
		t.Fatalf("ticket reused: %d", again.StatusCode)
	}
	next, _ := url.Parse(resp.Header.Get("Location"))
	skipWarning = true
	resp = get(linkHost, next.RequestURI())
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	_ = hu
	return resp.StatusCode, string(b), back.RequestURI()
}

func TestGitHubGatedLink(t *testing.T) {
	gh := fakeGitHubOrgs(t, "anna", []string{"acme"})
	cfg := server.Config{MaxSessionsPerIP: 100, GitHubClientID: "id", GitHubClientSecret: "s", GitHubURL: gh.URL, GitHubAPIURL: gh.URL}
	_, ctl, httpURL := startPublic(t, cfg)

	open := func(allow ...string) string {
		info := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: hostEcho(t), AllowGitHub: allow}}}), 5*time.Second)[0]
		u, _ := url.Parse(info.URL)
		return u.Host
	}

	// anna by name: let in, and the app never sees our cookie.
	if code, body := visit(t, httpURL, open("Anna")); code != 200 || !strings.HasPrefix(body, "host=") {
		t.Fatalf("named user: %d %q", code, body)
	}
	// anna through her organisation.
	if code, _ := visit(t, httpURL, open("@acme")); code != 200 {
		t.Fatalf("org member: %d", code)
	}
	// someone else's list: signed in, but refused.
	if code, body := visit(t, httpURL, open("bob", "@other")); code != http.StatusForbidden || !strings.Contains(body, "specific GitHub users") {
		t.Fatalf("not on the list: %d %q", code, body[:min(len(body), 200)])
	}
	// API clients get a plain 401, never a redirect.
	host := open("anna")
	if resp, _ := (tunnelReq{t, httpURL, host}).do("GET", "/", nil, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("api client: %d", resp.StatusCode)
	}
	// A ticket used in another browser (no binding cookie) is refused.
	host2 := open("anna")
	_, _, ticket := visitTicket(t, httpURL, host2)
	if resp, _ := (tunnelReq{t, httpURL, host2}).do("GET", ticket, nil, ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ticket from another browser: %d", resp.StatusCode)
	}
	// On a link without sign-in, our auth path never reaches the app.
	plain := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: hostEcho(t)}}}), 5*time.Second)[0]
	pu, _ := url.Parse(plain.URL)
	if resp, _ := (tunnelReq{t, httpURL, pu.Host}).do("GET", "/.publiclocal/auth?t=x", nil, ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("auth path on ungated link: %d", resp.StatusCode)
	}
	// A ticket minted for one link does not open another.
	if resp, _ := (tunnelReq{t, httpURL, host}).do("GET", "/.publiclocal/auth?t=forged.abc&next=/", nil, ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("forged ticket: %d", resp.StatusCode)
	}
}

func TestSSHOptions(t *testing.T) {
	_, sshAddr, httpURL := startSSH(t, server.Config{})
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "host=%s", r.Host) })

	c, _ := net.Dial("tcp", sshAddr)
	cc, chans, reqs, err := ssh.NewClientConn(c, "publiclocal", &ssh.ClientConfig{User: "x", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	cl := ssh.NewClient(cc, chans, reqs)
	defer cl.Close()
	ln, err := cl.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(ln, app)
	sess, _ := cl.NewSession()
	out, _ := sess.StdoutPipe()
	// Options as the command, as in: ssh -R0:localhost:3000 publiclocal.app password=s3cret expires=30m host-header=localhost
	if err := sess.Start("password=s3cret expires=30m host-header=localhost"); err != nil {
		t.Fatal(err)
	}
	var window strings.Builder
	link := ""
	buf := make([]byte, 4096)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !(link != "" && strings.Contains(window.String(), "Options:")) {
		n, err := out.Read(buf)
		window.Write(buf[:n])
		if i := strings.Index(window.String(), "Forwarding  "); i >= 0 && link == "" {
			rest := window.String()[i+12:]
			link = strings.Fields(rest)[0]
		}
		if err != nil {
			break
		}
	}
	if link == "" || !strings.Contains(window.String(), "password set") || !strings.Contains(window.String(), "expires in 30m") {
		t.Fatalf("ssh window: %q", window.String())
	}
	u, _ := url.Parse(link)
	q := tunnelReq{t, httpURL, u.Host}
	if resp, _ := q.do("GET", "/", nil, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("password not applied: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", httpURL+"/", nil)
	req.Host = u.Host
	req.SetBasicAuth("x", "s3cret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "host=localhost" {
		t.Fatalf("host-header not applied: %q", b)
	}

	// Bad options are reported in the window, not applied.
	c2, _ := net.Dial("tcp", sshAddr)
	cc2, ch2, rq2, _ := ssh.NewClientConn(c2, "publiclocal", &ssh.ClientConfig{User: "expires=forever", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	cl2 := ssh.NewClient(cc2, ch2, rq2)
	defer cl2.Close()
	s2, _ := cl2.NewSession()
	o2, _ := s2.StdoutPipe()
	s2.Shell()
	var w2 strings.Builder
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(w2.String(), "not applied") {
		n, err := o2.Read(buf)
		w2.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if !strings.Contains(w2.String(), "Options not applied") {
		t.Fatalf("bad user-name options: %q", w2.String())
	}
}
