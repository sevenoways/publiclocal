package e2e

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/proto"
	"github.com/sevenoways/publiclocal/internal/server"
)

func TestHomepage(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "index.html"), []byte("home"), 0o644)
	os.WriteFile(filepath.Join(dir, "terms.html"), []byte("terms"), 0o644)
	os.WriteFile(filepath.Join(dir, ".secret"), []byte("nope"), 0o644)
	_, ctl, httpURL := startPublic(t, server.Config{SiteDir: dir})
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	get := func(host, path string) (int, string, http.Header) {
		req, _ := http.NewRequest("GET", httpURL+path, nil)
		req.Host = host
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b), resp.Header
	}

	if code, body, h := get(domain, "/"); code != 200 || body != "home" || h.Get("Content-Security-Policy") == "" {
		t.Fatalf("homepage: %d %q", code, body)
	}
	if code, body, _ := get(domain, "/terms"); code != 200 || body != "terms" {
		t.Fatalf("/terms: %d %q", code, body)
	}
	if code, _, _ := get(domain, "/.secret"); code != 404 {
		t.Fatalf("dotfile served: %d", code)
	}
	if code, _, h := get("www."+domain, "/terms"); code != 301 || !strings.HasSuffix(h.Get("Location"), domain+"/terms") {
		t.Fatalf("www redirect: %d %q", code, h.Get("Location"))
	}

	// A tunnel still works next to the homepage.
	infos := startClient(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}})
	if code, body, _ := get(strings.TrimPrefix(infos[0].URL, "http://"), "/"); code != 200 || !strings.HasPrefix(body, "app") {
		t.Fatalf("tunnel next to homepage: %d %q", code, body)
	}
}

func TestReservedSubdomain(t *testing.T) {
	ctl, _ := startServer(t) // a private server, where custom names are allowed
	err := runQuiet(client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: "127.0.0.1:1", Subdomain: "www"}}})
	if !rejected(err) || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("www should be reserved, got %v", err)
	}
}
