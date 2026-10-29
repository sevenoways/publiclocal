// Package e2e runs a real server and client in-process and sends traffic through them.
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
	"testing"
	"time"

	"github.com/sevenoways/reverse-tunnel/internal/client"
	"github.com/sevenoways/reverse-tunnel/internal/proto"
	"github.com/sevenoways/reverse-tunnel/internal/server"
)

const domain = "tunnel.test"

func startServer(t *testing.T, tokens ...string) (ctlAddr string, httpURL string) {
	t.Helper()
	srv := server.New(server.Config{
		Domain:      domain,
		Tokens:      tokens,
		TCPPortMin:  20000,
		TCPPortMax:  29999,
		TCPBindHost: "127.0.0.1",
		Logger:      slog.New(slog.DiscardHandler),
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.ServeControl(ln)
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	return ln.Addr().String(), hs.URL
}

func startClient(t *testing.T, cfg client.Config) []proto.TunnelInfo {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ready := make(chan []proto.TunnelInfo, 1)
	errc := make(chan error, 1)
	cfg.Logger = slog.New(slog.DiscardHandler)
	cfg.OnReady = func(i []proto.TunnelInfo) { ready <- i }
	go func() { errc <- client.Run(ctx, cfg) }()
	select {
	case infos := <-ready:
		return infos
	case err := <-errc:
		t.Fatalf("client exited: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("client not ready")
	}
	return nil
}

func TestHTTPAndTCP(t *testing.T) {
	ctl, httpURL := startServer(t, "secret")

	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "host=%s path=%s proto=%s", r.Host, r.URL.Path, r.Header.Get("X-Forwarded-Proto"))
	}))
	defer web.Close()
	echo := startEcho(t)

	infos := startClient(t, client.Config{
		Server: ctl,
		Token:  "secret",
		Tunnels: []client.Tunnel{
			{Type: proto.TypeHTTP, Local: web.Listener.Addr().String(), Subdomain: "demo"},
			{Type: proto.TypeTCP, Local: echo},
		},
	})

	// HTTP: several requests so pooled streams are reused.
	for i := range 3 {
		req, _ := http.NewRequest("GET", httpURL+"/hello", nil)
		req.Host = "demo." + domain
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		want := "host=demo." + domain + " path=/hello proto=http"
		if string(body) != want {
			t.Fatalf("request %d: got %q, want %q", i, body, want)
		}
	}

	// Unknown subdomain.
	req, _ := http.NewRequest("GET", httpURL, nil)
	req.Host = "nope." + domain
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("unknown subdomain: status %d", resp.StatusCode)
	}

	// TCP.
	u, err := url.Parse(infos[1].URL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", u.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("ping"))
	c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "ping" {
		t.Fatalf("tcp echo: got %q, %v", got, err)
	}
}

func TestBadTokenRejected(t *testing.T) {
	ctl, _ := startServer(t, "secret")
	err := client.Run(context.Background(), client.Config{
		Server:  ctl,
		Token:   "wrong",
		Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1"}},
		Logger:  slog.New(slog.DiscardHandler),
	})
	var rej *client.RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("want RejectedError, got %v", err)
	}
}

func TestSubdomainTaken(t *testing.T) {
	ctl, _ := startServer(t)
	cfg := client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1", Subdomain: "dup"}}}
	startClient(t, cfg)
	cfg.Logger = slog.New(slog.DiscardHandler)
	err := client.Run(context.Background(), cfg)
	var rej *client.RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("want RejectedError, got %v", err)
	}
}

func startEcho(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(c, c)
				c.Close()
			}()
		}
	}()
	return ln.Addr().String()
}
