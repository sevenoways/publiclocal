package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/proto"
	"github.com/sevenoways/publiclocal/internal/server"
)

func TestAdminLinksAndForget(t *testing.T) {
	srv, ctl, _ := startPublic(t, server.Config{MaxSessionsPerIP: 100})
	admin := httptest.NewServer(srv.AdminHandler())
	defer admin.Close()

	ch, cancel := clientCtx(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}})
	off := next(t, ch, 5*time.Second)[0]
	on := next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}}), 5*time.Second)[0]
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for len(srv.Tunnels()) != 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	links := func() map[string]server.LinkStatus {
		resp, err := http.Get(admin.URL + "/links")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var list []server.LinkStatus
		json.NewDecoder(resp.Body).Decode(&list)
		out := map[string]server.LinkStatus{}
		for _, l := range list {
			out[l.Name] = l
		}
		return out
	}
	l := links()
	if len(l) != 2 || l[off.Name].Online || !l[on.Name].Online || l[off.Name].IP == "" || l[on.Name].Expires.IsZero() {
		t.Fatalf("links: %+v", l)
	}

	// Forget removes the offline link; the other is untouched; unknown names 404.
	if resp, _ := http.Post(admin.URL+"/forget?sub="+strings.ToUpper(off.Name), "", nil); resp.StatusCode != 200 {
		t.Fatalf("forget: %d", resp.StatusCode)
	}
	if l := links(); len(l) != 1 || !l[on.Name].Online {
		t.Fatalf("after forget: %+v", l)
	}
	if resp, _ := http.Post(admin.URL+"/forget?sub=nope", "", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("forget unknown: %d", resp.StatusCode)
	}
	// Forgetting an online link closes its tunnel too, and it is not banned.
	http.Post(admin.URL+"/forget?sub="+on.Name, "", nil)
	deadline = time.Now().Add(3 * time.Second)
	for len(srv.Tunnels()) != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(srv.Tunnels()); n != 0 {
		t.Fatalf("forget should close the tunnel, %d still open", n)
	}
	next(t, clientWatch(t, client.Config{Server: ctl, Tunnels: []client.Tunnel{{Type: proto.TypeHTTP, Local: webApp(t)}}}), 5*time.Second)
}
