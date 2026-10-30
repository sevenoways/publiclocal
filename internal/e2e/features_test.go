package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
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

func TestPasswordProtectedLink(t *testing.T) {
	_, ctl, httpURL := startPublic(t, server.Config{})
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "auth=%q", r.Header.Get("Authorization"))
	}))
	defer app.Close()
	info := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: app.Listener.Addr().String(), Password: "s3cret"}}}), 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	q := tunnelReq{t, httpURL, u.Host}

	resp, _ := q.do("GET", "/", nil, "")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Fatalf("no password: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	req, _ := http.NewRequest("GET", httpURL+"/", nil)
	req.Host = u.Host
	req.SetBasicAuth("anyone", "wrong")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", resp.StatusCode)
	}
	req.SetBasicAuth("anyone", "s3cret")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != 200 || string(body) != `auth=""` {
		t.Fatalf("right password: %d %s (the app must not see the link password)", resp2.StatusCode, body)
	}
}

func TestRequestEventsReachClient(t *testing.T) {
	_, ctl, httpURL := startPublic(t, server.Config{})
	events := make(chan proto.Event, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan []proto.TunnelInfo, 1)
	go client.Run(ctx, client.Config{
		Server: ctl, Logger: slog.New(slog.DiscardHandler),
		Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}},
		OnReady: func(i []proto.TunnelInfo) { ready <- i },
		OnEvent: func(e proto.Event) { events <- e },
	})
	info := next(t, ready, 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	tunnelReq{t, httpURL, u.Host}.do("GET", "/hello?x=1", nil, "")

	select {
	case ev := <-events:
		if ev.Method != "GET" || ev.Path != "/hello?x=1" || ev.Status != 200 || ev.Remote == "" {
			t.Fatalf("event: %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no request event reached the client")
	}
}

func TestLinkStatsAndStatusEndpoint(t *testing.T) {
	srv, ctl, httpURL := startPublic(t, server.Config{MaxSessionsPerIP: 100})
	ch, cancel := clientCtx(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}})
	info := next(t, ch, 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	q := tunnelReq{t, httpURL, u.Host}
	for range 3 {
		q.do("GET", "/", nil, "")
	}

	status := func() map[string]any {
		_, body := q.do("GET", "/.publiclocal/status", nil, "")
		var m map[string]any
		json.Unmarshal([]byte(body), &m)
		return m
	}
	if st := status(); st["state"] != "online" || st["requests"] != float64(3) || st["visitors"] != float64(1) {
		t.Fatalf("online status: %v", st)
	}

	// Offline: counters survive the disconnect and show on the page.
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for status()["state"] != "offline" && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if st := status(); st["state"] != "offline" || st["requests"] != float64(3) || st["last_online"] == nil {
		t.Fatalf("offline status: %v", st)
	}
	if _, body := q.do("GET", "/", browserHdr, ""); !strings.Contains(body, "3 requests from 1 visitor") || !strings.Contains(body, "Last online") {
		t.Fatalf("offline page lacks stats: %s", body[:min(len(body), 400)])
	}

	// Expired: the summary moves to history and the gone page shows it.
	srv.Kill(info.Name, "")
	_, ctl2, httpURL2 := startPublic(t, server.Config{MaxSessionsPerIP: 100, MaxTunnelAge: 600 * time.Millisecond})
	info2 := next(t, clientWatch(t, client.Config{Server: ctl2, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}}), 5*time.Second)[0]
	u2, _ := url.Parse(info2.URL)
	q2 := tunnelReq{t, httpURL2, u2.Host}
	q2.do("GET", "/a", nil, "")
	q2.do("GET", "/b", nil, "")
	time.Sleep(900 * time.Millisecond)
	resp, body := q2.do("GET", "/", browserHdr, "")
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Live from") || !strings.Contains(body, "2 requests") {
		t.Fatalf("gone page: %d %s", resp.StatusCode, body[:min(len(body), 400)])
	}
	if st := func() map[string]any {
		_, b := q2.do("GET", "/.publiclocal/status", nil, "")
		var m map[string]any
		json.Unmarshal([]byte(b), &m)
		return m
	}(); st["state"] != "expired" || st["requests"] != float64(2) {
		t.Fatalf("expired status: %v", st)
	}
}
