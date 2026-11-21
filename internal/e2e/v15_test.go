package e2e

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/proto"
	"github.com/sevenoways/publiclocal/internal/server"
)

// echoApp reports the path, a header and the forwarded user it received.
func echoApp(t *testing.T) string {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("path=" + r.URL.RequestURI() + " env=" + r.Header.Get("X-Env") + " user=" + r.Header.Get("X-Forwarded-User")))
	}))
	t.Cleanup(app.Close)
	return app.Listener.Addr().String()
}

func basic(user, pw string) map[string]string {
	req, _ := http.NewRequest("GET", "http://x/", nil)
	req.SetBasicAuth(user, pw)
	return map[string]string{"Authorization": req.Header.Get("Authorization")}
}

func TestNamedUsers(t *testing.T) {
	_, ctl, httpURL := startPublic(t, server.Config{MaxSessionsPerIP: 100})
	var mu sync.Mutex
	var seen []client.Captured
	info := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: echoApp(t), Users: []string{"Anna:pw1", "bob:pw2"}}},
		OnRequest: func(c client.Captured) { mu.Lock(); seen = append(seen, c); mu.Unlock() }}), 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	q := tunnelReq{t, httpURL, u.Host}
	if resp, _ := q.do("GET", "/", nil, ""); resp.StatusCode != 401 {
		t.Fatalf("no credentials: %d", resp.StatusCode)
	}
	if resp, _ := q.do("GET", "/", basic("anna", "pw2"), ""); resp.StatusCode != 401 {
		t.Fatalf("wrong password for a user: %d", resp.StatusCode)
	}
	if resp, _ := q.do("GET", "/", basic("carol", "pw1"), ""); resp.StatusCode != 401 {
		t.Fatalf("unknown user: %d", resp.StatusCode)
	}
	// A visitor cannot claim to be someone else through the header.
	h := basic("ANNA", "pw1")
	h["X-Forwarded-User"] = "bob"
	if resp, body := q.do("GET", "/", h, ""); resp.StatusCode != 200 || !strings.HasSuffix(body, "user=anna") {
		t.Fatalf("named user: %d %q", resp.StatusCode, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0].User != "anna" {
		t.Fatalf("captured user: %+v", seen)
	}
}

func TestNoUserHeaderWithoutGate(t *testing.T) {
	_, ctl, httpURL := startPublic(t, server.Config{MaxSessionsPerIP: 100})
	info := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: echoApp(t)}}}), 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	if _, body := (tunnelReq{t, httpURL, u.Host}).do("GET", "/", map[string]string{"X-Forwarded-User": "root"}, ""); !strings.HasSuffix(body, "user=") {
		t.Fatalf("spoofed user header reached the app: %q", body)
	}
}

func TestEdgeRules(t *testing.T) {
	ctl, httpURL := startServer(t)
	rules := client.Rules{Headers: http.Header{"X-Env": {"staging"}}, Rewrites: []client.PathRewrite{{From: "/api", To: "/v2/api"}}, Blocks: []string{"/admin/*", "/secret"}}
	info := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: echoApp(t)}}, Rules: rules}), 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	q := tunnelReq{t, httpURL, u.Host}
	if _, body := q.do("GET", "/api/users?x=1", map[string]string{"X-Env": "prod"}, ""); !strings.HasPrefix(body, "path=/v2/api/users?x=1 env=staging") {
		t.Fatalf("rewrite and header: %q", body)
	}
	if _, body := q.do("GET", "/apiary", nil, ""); !strings.HasPrefix(body, "path=/apiary") {
		t.Fatalf("prefix must match whole segments: %q", body)
	}
	for _, p := range []string{"/admin/users", "/admin", "/secret", "//secret", "/admin/../secret", "/Admin/x", "/admin;x/y", "/SECRET"} {
		if resp, _ := q.do("GET", p, nil, ""); resp.StatusCode != 403 {
			t.Fatalf("%s should be blocked: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := q.do("GET", "/administrator", nil, ""); resp.StatusCode != 200 {
		t.Fatalf("/administrator should pass: %d", resp.StatusCode)
	}
}
