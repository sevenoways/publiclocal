package e2e

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/proto"
)

// htmlApp serves a page and records what reached it.
func htmlApp(t *testing.T, hits *[]string, mu *sync.Mutex) string {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		*hits = append(*hits, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h1>app</h1></body></html>")
	}))
	t.Cleanup(app.Close)
	return app.Listener.Addr().String()
}

func TestLinkExtras(t *testing.T) {
	ctl, httpURL := startServer(t)
	var mu sync.Mutex
	var hits []string
	var feedback []client.Feedback
	var captured []client.Captured
	dir := t.TempDir()
	users := filepath.Join(dir, "users.json")
	os.WriteFile(users, []byte(`[{"name":"anna"}]`), 0o600)
	m1, _ := client.ParseMock("/api/users=" + users)
	m2, _ := client.ParseMock("POST /pay=402")
	v, _ := client.ParseVerifier("github:topsecret")
	v.Strict = true
	key := "k3y0123456789abcdef"
	info := next(t, clientWatch(t, client.Config{
		Server:   ctl,
		Tunnels:  []client.Tunnel{{Type: proto.TypeHTTP, Local: htmlApp(t, &hits, &mu)}},
		Mocks:    []client.Mock{m1, m2},
		Verify:   v,
		Feedback: true,
		LiveKey:  key,
		OnFeedback: func(f client.Feedback) {
			mu.Lock()
			feedback = append(feedback, f)
			mu.Unlock()
		},
		OnRequest: func(c client.Captured) {
			mu.Lock()
			captured = append(captured, c)
			mu.Unlock()
		},
	}), 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	q := tunnelReq{t, httpURL, u.Host}
	sig := func(body string) map[string]string {
		m := hmac.New(sha256.New, []byte("topsecret"))
		m.Write([]byte(body))
		return map[string]string{"X-Hub-Signature-256": "sha256=" + hex.EncodeToString(m.Sum(nil)), "Content-Type": "application/json"}
	}

	// Live viewer: wrong key is a 404; the right key streams events.
	if resp, _ := q.do("GET", "/.publiclocal/live?k=wrong", nil, ""); resp.StatusCode != 404 {
		t.Fatalf("live with wrong key: %d", resp.StatusCode)
	}
	if resp, body := q.do("GET", "/.publiclocal/live?k="+key, nil, ""); resp.StatusCode != 200 || !strings.Contains(body, "Live requests") {
		t.Fatalf("live page: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", httpURL+"/.publiclocal/live/events?k="+key, nil)
	req.Host = u.Host
	stream, err := http.DefaultClient.Do(req)
	if err != nil || stream.StatusCode != 200 {
		t.Fatalf("live stream: %v %v", err, stream)
	}
	defer stream.Body.Close()
	events := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(stream.Body)
		for sc.Scan() {
			if l := sc.Text(); strings.HasPrefix(l, "data: ") {
				events <- l
			}
		}
	}()

	// Strict signature check: unsigned refused, signed passes.
	if resp, _ := q.do("POST", "/hook", map[string]string{"Content-Type": "application/json"}, `{"a":1}`); resp.StatusCode != 401 {
		t.Fatalf("unsigned webhook: %d", resp.StatusCode)
	}
	if resp, _ := q.do("POST", "/hook", sig(`{"a":1}`), `{"a":1}`); resp.StatusCode != 200 {
		t.Fatalf("signed webhook: %d", resp.StatusCode)
	}

	// Mocks answer without the app.
	if resp, body := q.do("GET", "/api/users?x=1", sig(""), ""); resp.StatusCode != 200 || body != `[{"name":"anna"}]` || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("mock file: %d %q %q", resp.StatusCode, body, resp.Header.Get("Content-Type"))
	}
	if resp, _ := q.do("POST", "/pay", sig(""), ""); resp.StatusCode != 402 {
		t.Fatalf("mock status: %d", resp.StatusCode)
	}

	// The feedback button is added to HTML pages, and comments arrive cleaned.
	h := sig("")
	h["Accept"] = "text/html"
	h["Accept-Encoding"] = "gzip"
	if _, body := q.do("GET", "/", h, ""); !strings.Contains(body, `/.publiclocal/feedback.js`) {
		t.Fatalf("widget not injected: %q", body)
	}
	if resp, body := q.do("GET", "/.publiclocal/feedback.js", nil, ""); resp.StatusCode != 200 || !strings.Contains(body, "attachShadow") {
		t.Fatalf("widget script: %d", resp.StatusCode)
	}
	if resp, _ := q.do("POST", "/.publiclocal/feedback", map[string]string{"Content-Type": "application/json", "Origin": "https://evil.example"}, `{"text":"x"}`); resp.StatusCode != 403 {
		t.Fatalf("cross-site feedback: %d", resp.StatusCode)
	}
	if resp, _ := q.do("POST", "/.publiclocal/feedback", map[string]string{"Content-Type": "application/json"}, `{"page":"/pricing","name":"Bo\u001b[31mb","text":"Looks great\u001b]0;x\u0007"}`); resp.StatusCode != 204 {
		t.Fatalf("feedback: %d", resp.StatusCode)
	}

	mu.Lock()
	if len(feedback) != 1 || feedback[0].Page != "/pricing" || strings.ContainsAny(feedback[0].Name+feedback[0].Text, "\x1b\x07") {
		t.Fatalf("feedback received: %+v", feedback)
	}
	for _, h := range hits {
		if strings.Contains(h, "/api/users") || strings.Contains(h, "/pay") || strings.Contains(h, ".publiclocal") {
			t.Fatalf("app saw a request it should not have: %v", hits)
		}
	}
	verified := map[string]bool{}
	for _, c := range captured {
		verified[c.Verified] = true
		if strings.Contains(c.Path, ".publiclocal") {
			t.Fatalf("internal path captured: %s", c.Path)
		}
	}
	mu.Unlock()
	if !verified["valid"] || !verified["no X-Hub-Signature-256 header"] {
		t.Fatalf("verify results: %v", verified)
	}

	// The live stream saw requests, without query strings.
	deadline := time.After(3 * time.Second)
	sawMock := false
	for !sawMock {
		select {
		case e := <-events:
			if strings.Contains(e, "?x=1") {
				t.Fatalf("query leaked to live view: %s", e)
			}
			sawMock = strings.Contains(e, `"/api/users"`)
		case <-deadline:
			t.Fatal("live view got no events")
		}
	}
}

func TestChaos(t *testing.T) {
	ctl, httpURL := startServer(t)
	info := next(t, clientWatch(t, client.Config{
		Server:  ctl,
		Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: hostEcho(t)}},
		Chaos:   client.Chaos{LatencyMin: 150 * time.Millisecond, LatencyMax: 150 * time.Millisecond, FailRate: 1},
	}), 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	start := time.Now()
	resp, _ := (tunnelReq{t, httpURL, u.Host}).do("GET", "/", nil, "")
	if resp.StatusCode != 503 || resp.Header.Get("PublicLocal-Simulated") != "fail" || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("chaos: %d after %v", resp.StatusCode, time.Since(start))
	}
}
