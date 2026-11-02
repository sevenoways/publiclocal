package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/proto"
	"github.com/sevenoways/publiclocal/internal/server"
)

// domainCall is api() for the domains endpoints, which return their own shapes.
func domainCall(t *testing.T, httpURL, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, httpURL+path, rd)
	req.Host = domain
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// fakeGitHubUsers answers each sign-in with the next login in the list.
func fakeGitHubUsers(t *testing.T, logins ...string) *httptest.Server {
	var mu sync.Mutex
	n := 0
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			json.NewEncoder(w).Encode(map[string]string{"access_token": "gh-token"})
		case "/user":
			mu.Lock()
			login := logins[min(n, len(logins)-1)]
			id := n + 1
			n++
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]any{"login": login, "id": id, "created_at": time.Now().AddDate(-2, 0, 0)})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(gh.Close)
	return gh
}

func TestCustomDomains(t *testing.T) {
	gh := fakeGitHubUsers(t, "octocat", "squatter")
	var mu sync.Mutex
	txt := map[string][]string{} // the fake DNS
	cfg := server.Config{MaxSessionsPerIP: 100, GitHubClientID: "id", GitHubClientSecret: "secret", GitHubURL: gh.URL, GitHubAPIURL: gh.URL,
		LookupTXT: func(_ context.Context, name string) ([]string, error) {
			mu.Lock()
			defer mu.Unlock()
			if r, ok := txt[name]; ok {
				return r, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}}
	_, ctl, httpURL := startPublic(t, cfg)
	token, _ := login(t, httpURL)

	// Bad names are refused; a good one gives the records to set.
	for _, bad := range []string{"example.com", "x." + domain, "not a host"} {
		if code, _ := domainCall(t, httpURL, "POST", "/api/domains", token, map[string]string{"host": bad}); code != 400 {
			t.Errorf("%q should be refused: %d", bad, code)
		}
	}
	code, add := domainCall(t, httpURL, "POST", "/api/domains", token, map[string]string{"host": "Demo.Example.com"})
	if code != 200 || add["host"] != "demo.example.com" || add["txt_name"] != "_publiclocal.demo.example.com" || add["cname"] != domain {
		t.Fatalf("add: %d %v", code, add)
	}
	value := add["txt_value"].(string)
	if !strings.HasPrefix(value, "publiclocal-verify=") {
		t.Fatalf("txt value: %q", value)
	}

	// Not verified yet: attaching fails, visiting the name is a 404.
	if code, out := domainCall(t, httpURL, "POST", "/api/domains/verify", token, map[string]string{"host": "demo.example.com"}); code != 409 || !strings.Contains(out["error"].(string), "no TXT record") {
		t.Fatalf("verify without DNS: %d %v", code, out)
	}
	runUnverified := client.Config{Server: ctl, Account: token, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: hostEcho(t), Domain: "demo.example.com"}}}
	if err := client.Run(context.Background(), runUnverified); err == nil || !strings.Contains(err.Error(), "not verified") {
		t.Fatalf("attach before verify: %v", err)
	}

	// A wrong token is refused; the right one verifies.
	mu.Lock()
	txt["_publiclocal.demo.example.com"] = []string{"v=spf1", "publiclocal-verify=someone-else"}
	mu.Unlock()
	if code, _ := domainCall(t, httpURL, "POST", "/api/domains/verify", token, map[string]string{"host": "demo.example.com"}); code != 409 {
		t.Fatalf("wrong token accepted: %d", code)
	}
	mu.Lock()
	txt["_publiclocal.demo.example.com"] = []string{"v=spf1", value}
	mu.Unlock()
	if code, out := domainCall(t, httpURL, "POST", "/api/domains/verify", token, map[string]string{"host": "demo.example.com"}); code != 200 || out["verified"] != true {
		t.Fatalf("verify: %d %v", code, out)
	}

	// Attach a link and visit it through the custom name.
	infos := next(t, clientWatch(t, runUnverified), 5*time.Second)
	if infos[0].Domain != "demo.example.com" {
		t.Fatalf("info: %+v", infos[0])
	}
	q := tunnelReq{t, httpURL, "demo.example.com"}
	if resp, body := q.do("GET", "/hello", nil, ""); resp.StatusCode != 200 || !strings.HasPrefix(body, "host=demo.example.com") {
		t.Fatalf("via custom domain: %d %q", resp.StatusCode, body)
	}
	if resp, _ := (tunnelReq{t, httpURL, "other.example.com"}).do("GET", "/", nil, ""); resp.StatusCode != 404 {
		t.Fatalf("unknown name: %d", resp.StatusCode)
	}
	// Another account cannot take the name, and nobody can attach it twice.
	if code, _ := domainCall(t, httpURL, "POST", "/api/domains", "bad-token", map[string]string{"host": "demo.example.com"}); code != 401 {
		t.Fatalf("anonymous add: %d", code)
	}
	if err := client.Run(context.Background(), client.Config{Server: ctl, Account: token, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: hostEcho(t), Domain: "demo.example.com"}}}); err == nil || !strings.Contains(err.Error(), "another live link") {
		t.Fatalf("double attach: %v", err)
	}
	if code, out := domainCall(t, httpURL, "GET", "/api/domains", token, nil); code != 200 || len(out["domains"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}
	// A squatter cannot block the real owner: an unverified entry by another
	// account is displaced, a verified one is not.
	token2, _ := login(t, httpURL)
	if code, _ := domainCall(t, httpURL, "POST", "/api/domains", token2, map[string]string{"host": "demo.example.com"}); code != 409 {
		t.Fatalf("verified name taken by another account: %d", code)
	}
	if code, _ := domainCall(t, httpURL, "POST", "/api/domains", token2, map[string]string{"host": "new.example.com"}); code != 200 {
		t.Fatalf("squatter add: %d", code)
	}
	if code, _ := domainCall(t, httpURL, "POST", "/api/domains", token, map[string]string{"host": "new.example.com"}); code != 200 {
		t.Fatalf("displacing an unverified entry: %d", code)
	}
	// Verification is rate limited per account.
	limited := false
	for range 8 {
		if code, _ := domainCall(t, httpURL, "POST", "/api/domains/verify", token2, map[string]string{"host": "nope.example.com"}); code == 429 {
			limited = true
		}
	}
	if !limited {
		t.Fatal("verify is not rate limited")
	}
	// Removing the name stops traffic at once.
	domainCall(t, httpURL, "POST", "/api/domains/remove", token, map[string]string{"host": "demo.example.com"})
	if resp, _ := q.do("GET", "/hello", nil, ""); resp.StatusCode != 404 {
		t.Fatalf("after remove: %d", resp.StatusCode)
	}
}

func TestGitHubGateOnCustomDomain(t *testing.T) {
	gh := fakeGitHubOrgs(t, "anna", nil)
	var mu sync.Mutex
	txt := map[string][]string{}
	cfg := server.Config{MaxSessionsPerIP: 100, GitHubClientID: "id", GitHubClientSecret: "s", GitHubURL: gh.URL, GitHubAPIURL: gh.URL,
		LookupTXT: func(_ context.Context, name string) ([]string, error) {
			mu.Lock()
			defer mu.Unlock()
			return txt[name], nil
		}}
	_, ctl, httpURL := startPublic(t, cfg)
	token, _ := login(t, httpURL)
	_, add := domainCall(t, httpURL, "POST", "/api/domains", token, map[string]string{"host": "gated.example.com"})
	mu.Lock()
	txt["_publiclocal.gated.example.com"] = []string{add["txt_value"].(string)}
	mu.Unlock()
	if code, _ := domainCall(t, httpURL, "POST", "/api/domains/verify", token, map[string]string{"host": "gated.example.com"}); code != 200 {
		t.Fatalf("verify: %d", code)
	}
	next(t, clientWatch(t, client.Config{Server: ctl, Account: token, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: hostEcho(t), Domain: "gated.example.com", AllowGitHub: []string{"anna"}}}}), 5*time.Second)
	// The whole sign-in round trip works on the custom name, and the app sees it.
	if code, body := visit(t, httpURL, "gated.example.com"); code != 200 || !strings.HasPrefix(body, "host=gated.example.com") {
		t.Fatalf("gated custom domain: %d %q", code, body)
	}
}
