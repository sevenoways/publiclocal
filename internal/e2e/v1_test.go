package e2e

import (
	"bufio"
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

func TestMultiPortAndExpires(t *testing.T) {
	_, ctl, httpURL := startPublic(t, server.Config{MaxSessionsPerIP: 100})
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "A") }))
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "B") }))
	defer a.Close()
	defer b.Close()
	infos := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{
		{Type: proto.TypeHTTP, Local: a.Listener.Addr().String()},
		{Type: proto.TypeHTTP, Local: b.Listener.Addr().String(), MaxAge: 90 * time.Minute},
	}}), 5*time.Second)
	if len(infos) != 2 || infos[0].URL == infos[1].URL {
		t.Fatalf("two links expected: %+v", infos)
	}
	for i, want := range []string{"A", "B"} {
		u, _ := url.Parse(infos[i].URL)
		if _, body := (tunnelReq{t, httpURL, u.Host}).do("GET", "/", nil, ""); body != want {
			t.Fatalf("tunnel %d: got %q", i, body)
		}
	}
	if d := time.Until(infos[1].Expires); d > 91*time.Minute || d < 80*time.Minute {
		t.Fatalf("--expires 90m not applied: expires in %v", d)
	}
	if d := time.Until(infos[0].Expires); d < 23*time.Hour {
		t.Fatalf("default lifetime changed: %v", d)
	}
}

func TestNoteAndVisitorLimit(t *testing.T) {
	_, ctl, httpURL := startPublic(t, server.Config{})
	info := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t), Note: "Staging build for Anna", MaxVisitors: 1}}}), 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	q := tunnelReq{t, httpURL, u.Host}
	if _, body := q.do("GET", "/", browserHdr, ""); !strings.Contains(body, "Staging build for Anna") {
		t.Fatal("note missing from the warning page")
	}
	if resp, _ := q.do("GET", "/", nil, ""); resp.StatusCode != 200 {
		t.Fatalf("first visitor: %d", resp.StatusCode)
	}
	// A second network is turned away once the one allowed place is taken.
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	cl := &http.Client{Transport: &http.Transport{DialContext: d.DialContext}}
	req, _ := http.NewRequest("GET", httpURL+"/", nil)
	req.Host = u.Host
	resp, err := cl.Do(req)
	if err != nil {
		t.Skipf("cannot dial from 127.0.0.2 here: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("second network should get 410, got %d", resp.StatusCode)
	}
	if resp, _ := q.do("GET", "/again", nil, ""); resp.StatusCode != 200 {
		t.Fatalf("admitted visitor should keep access: %d", resp.StatusCode)
	}
}

func TestCORSAndBadge(t *testing.T) {
	srv, ctl, httpURL := startPublic(t, server.Config{})
	ch, cancel := clientCtx(t, client.Config{Server: ctl, CORS: true, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}})
	info := next(t, ch, 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	q := tunnelReq{t, httpURL, u.Host}
	resp, _ := q.do("OPTIONS", "/api", map[string]string{"Origin": "https://app.example", "Access-Control-Request-Method": "POST"}, "")
	if resp.StatusCode != http.StatusNoContent || resp.Header.Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatalf("preflight: %d %q", resp.StatusCode, resp.Header.Get("Access-Control-Allow-Origin"))
	}
	if resp, body := q.do("GET", "/", map[string]string{"Origin": "https://app.example"}, ""); resp.Header.Get("Access-Control-Allow-Origin") == "" || !strings.HasPrefix(body, "app") {
		t.Fatalf("cors on response: %v %q", resp.Header, body)
	}
	if resp, body := q.do("GET", "/.publiclocal/badge.svg", nil, ""); !strings.Contains(resp.Header.Get("Content-Type"), "svg") || !strings.Contains(body, ">online<") {
		t.Fatalf("badge online: %q", body)
	}
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, body := q.do("GET", "/.publiclocal/badge.svg", nil, ""); strings.Contains(body, ">offline<") {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = srv
	t.Fatal("badge did not turn offline")
}

// TestWebSocketUpgrade sends a raw Upgrade request through the tunnel and
// echoes bytes both ways, which exercises hijacking in the new client path.
func TestWebSocketUpgrade(t *testing.T) {
	_, ctl, httpURL := startPublic(t, server.Config{})
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "echo" {
			http.Error(w, "upgrade required", 426)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
		rw.Flush()
		io.Copy(conn, rw)
	}))
	defer app.Close()
	info := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: app.Listener.Addr().String()}}}), 5*time.Second)[0]
	u, _ := url.Parse(info.URL)
	hu, _ := url.Parse(httpURL)
	c, err := net.Dial("tcp", hu.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(c, "GET /ws HTTP/1.1\r\nHost: %s\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n", u.Host)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	c.Write([]byte("ping over the tunnel"))
	buf := make([]byte, 64)
	n, err := br.Read(buf)
	if err != nil || string(buf[:n]) != "ping over the tunnel" {
		t.Fatalf("echo: %q %v", buf[:n], err)
	}
}
