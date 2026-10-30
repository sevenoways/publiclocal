package e2e

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/proto"
	"github.com/sevenoways/publiclocal/internal/server"
)

// clientCtx is clientWatch with a cancel the test can call to disconnect.
func clientCtx(t *testing.T, cfg client.Config) (<-chan []proto.TunnelInfo, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ch := make(chan []proto.TunnelInfo, 8)
	cfg.Logger = slog.New(slog.DiscardHandler)
	cfg.OnReady = func(i []proto.TunnelInfo) { ch <- i }
	go client.Run(ctx, cfg)
	return ch, cancel
}

// Visitors get a proper page and status code when a link is offline, gone
// or its app is down; API clients get plain text with the same codes.
func TestStatusPages(t *testing.T) {
	srv, ctl, httpURL := startPublic(t, server.Config{MaxSessionsPerIP: 100})
	curl := map[string]string{"User-Agent": "curl/8.0"}

	// App down: the tunnel is up but nothing listens locally.
	down := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1"}}}), 5*time.Second)[0]
	u, _ := url.Parse(down.URL)
	q := tunnelReq{t, httpURL, u.Host}
	if resp, body := q.do("GET", "/", curl, ""); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "not responding") {
		t.Fatalf("app down: %d %q", resp.StatusCode, body)
	}

	// Offline: the client went away but the link is still reserved.
	ctx, cancel := clientCtx(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}})
	off := next(t, ctx, 5*time.Second)[0]
	cancel()
	u2, _ := url.Parse(off.URL)
	q2 := tunnelReq{t, httpURL, u2.Host}
	deadline := time.Now().Add(3 * time.Second)
	var resp *http.Response
	var body string
	for time.Now().Before(deadline) {
		resp, body = q2.do("GET", "/", browserHdr, "")
		if resp.StatusCode == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" || !strings.Contains(body, "offline right now") || !strings.Contains(body, "<html") {
		t.Fatalf("offline page: %d retry=%q %q", resp.StatusCode, resp.Header.Get("Retry-After"), body[:min(len(body), 80)])
	}
	if resp, body := q2.do("GET", "/", curl, ""); resp.StatusCode != http.StatusServiceUnavailable || strings.Contains(body, "<html") {
		t.Fatalf("offline for curl should be plain text 503: %d %q", resp.StatusCode, body)
	}

	// Gone: never existed, or suspended.
	gone := tunnelReq{t, httpURL, "nope." + domain}
	if resp, body := gone.do("GET", "/", browserHdr, ""); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "has expired") || !strings.Contains(body, "Make your own") {
		t.Fatalf("gone page: %d %q", resp.StatusCode, body[:min(len(body), 80)])
	}
	srv.Suspend(off.Name)
	if resp, _ := q2.do("GET", "/", curl, ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("suspended link should be 404, got %d", resp.StatusCode)
	}
}
