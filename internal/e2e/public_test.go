package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

func startPublic(t *testing.T, cfg server.Config) (*server.Server, string, string) {
	t.Helper()
	cfg.Domain = domain
	cfg.Public = true
	cfg.AbuseContact = "mailto:abuse@example.com"
	cfg.Logger = slog.New(slog.DiscardHandler)
	srv := server.New(cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.ServeControl(ln)
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	return srv, ln.Addr().String(), hs.URL
}

func webApp(t *testing.T) string {
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "app cookies=%q", r.Header.Get("Cookie"))
	}))
	t.Cleanup(web.Close)
	return web.Listener.Addr().String()
}

func rejected(err error) bool {
	var rej *client.RejectedError
	return errors.As(err, &rej)
}

func runQuiet(cfg client.Config) error {
	cfg.Logger = slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return client.Run(ctx, cfg)
}

func TestPublicWarningPage(t *testing.T) {
	_, ctl, httpURL := startPublic(t, server.Config{})
	infos := startClient(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}})
	u, _ := url.Parse(infos[0].URL)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	get := func(header map[string]string) (*http.Response, string) {
		req, _ := http.NewRequest("GET", httpURL+"/page?x=1", nil)
		req.Host = u.Host
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(b)
	}
	browser := map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "text/html,*/*"}

	// A browser sees the warning page first.
	_, body := get(browser)
	if !strings.Contains(body, "temporary developer link") || !strings.Contains(body, "abuse@example.com") {
		t.Fatalf("expected warning page, got %q", body)
	}

	// Non-browser clients and the skip header go straight through.
	if _, body := get(nil); !strings.HasPrefix(body, "app") {
		t.Fatalf("curl-like request should reach app, got %q", body)
	}
	if _, body := get(map[string]string{"User-Agent": "Mozilla/5.0", "Accept": "text/html", "PublicLocal-Skip-Warning": "1"}); !strings.HasPrefix(body, "app") {
		t.Fatalf("skip header should reach app, got %q", body)
	}

	// Continuing sets a cookie and redirects back, but never off-site.
	form := url.Values{"next": {"//evil.example/x"}}
	req, _ := http.NewRequest("POST", httpURL+"/.publiclocal/continue", strings.NewReader(form.Encode()))
	req.Host = u.Host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+u.Host)
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/" {
		t.Fatalf("open redirect: Location %q", loc)
	}
	cookie := resp.Cookies()[0]

	// With the cookie the browser reaches the app, and the app never sees our cookie.
	browser["Cookie"] = cookie.Name + "=" + cookie.Value + "; session=abc"
	if _, body := get(browser); body != `app cookies="session=abc"` {
		t.Fatalf("after continue got %q", body)
	}
}

func TestPublicRestrictions(t *testing.T) {
	_, ctl, _ := startPublic(t, server.Config{MaxSessionsPerIP: 2})

	if err := runQuiet(client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeTCP, Local: "127.0.0.1:1"}}}); !rejected(err) {
		t.Fatalf("tcp should be rejected, got %v", err)
	}
	if err := runQuiet(client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1", Subdomain: "paypal"}}}); !rejected(err) {
		t.Fatalf("custom subdomain should be rejected, got %v", err)
	}

	cfg := client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1"}}}
	startClient(t, cfg)
	startClient(t, cfg)
	if err := runQuiet(cfg); !rejected(err) {
		t.Fatalf("third session from one IP should be rejected, got %v", err)
	}
}

func TestPublicRateLimitAndExpiry(t *testing.T) {
	_, ctl, httpURL := startPublic(t, server.Config{RequestsPerMinute: 2, MaxTunnelAge: 500 * time.Millisecond})
	infos := startClient(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}})
	u, _ := url.Parse(infos[0].URL)

	status := func() int {
		req, _ := http.NewRequest("GET", httpURL, nil)
		req.Host = u.Host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if a, b, c := status(), status(), status(); a != 200 || b != 200 || c != http.StatusTooManyRequests {
		t.Fatalf("rate limit: got %d %d %d", a, b, c)
	}
	time.Sleep(time.Second)
	if s := status(); s != http.StatusNotFound {
		t.Fatalf("expired tunnel should be gone, got %d", s)
	}
}

func TestAdminKillAndBan(t *testing.T) {
	srv, ctl, _ := startPublic(t, server.Config{})
	admin := httptest.NewServer(srv.AdminHandler())
	defer admin.Close()

	startClient(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1"}}})
	if n := len(srv.Tunnels()); n != 1 {
		t.Fatalf("want 1 tunnel, got %d", n)
	}
	resp, err := http.Post(admin.URL+"/ban?ip=127.0.0.1", "", nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("ban: %v %v", resp.Status, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(srv.Tunnels()) != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(srv.Tunnels()); n != 0 {
		t.Fatalf("ban should close sessions, %d left", n)
	}
	err = runQuiet(client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1"}}})
	if !rejected(err) || !strings.Contains(err.Error(), "banned") {
		t.Fatalf("banned IP should be rejected, got %v", err)
	}
}
