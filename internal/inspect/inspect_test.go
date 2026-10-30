package inspect

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sevenoways/publiclocal/internal/client"
)

func TestStoreReplayAndHandler(t *testing.T) {
	var hits atomic.Int32
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "got %s %s host=%s", r.Method, body, r.Host)
	}))
	defer app.Close()

	s := NewStore(3)
	e := s.Add(client.Captured{
		Time: time.Now(), Local: app.Listener.Addr().String(), Method: "POST", Path: "/hook?x=1", Host: "k7xq2m.publiclocal.app",
		Status: 200, Duration: 5 * time.Millisecond, Remote: "203.0.113.5", ReqHeader: http.Header{"Content-Type": {"application/json"}}, ReqBody: []byte(`{"id":1}`),
	})
	re, err := s.Replay(e.ID)
	if err != nil || re.ReplayOf != e.ID || re.Status != 200 || !strings.Contains(re.RespBody, `got POST {"id":1} host=k7xq2m.publiclocal.app`) {
		t.Fatalf("replay: %+v %v", re, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("app hit %d times", hits.Load())
	}
	if _, err := s.Replay(999); err == nil {
		t.Fatal("replaying a missing id should fail")
	}

	// Ring buffer keeps only the latest entries.
	for range 5 {
		s.Add(client.Captured{Method: "GET", Path: "/x"})
	}
	if l := s.List(); len(l) != 3 || l[0].ID <= l[1].ID {
		t.Fatalf("list: %d entries, first ids %d %d", len(l), l[0].ID, l[1].ID)
	}

	sum := s.Summary()
	if sum.Requests != 3 || len(sum.TopPaths) == 0 || !strings.HasPrefix(sum.TopPaths[0], "/x (3)") {
		t.Fatalf("summary: %+v", sum)
	}

	h := httptest.NewServer(s.Handler(func() []string { return []string{"https://k7x.example"} }))
	defer h.Close()
	resp, _ := http.Get(h.URL + "/api/requests")
	var list []Entry
	json.NewDecoder(resp.Body).Decode(&list)
	if len(list) != 3 {
		t.Fatalf("api: %d entries", len(list))
	}
	page, _ := http.Get(h.URL + "/")
	b, _ := io.ReadAll(page.Body)
	if !strings.Contains(string(b), "PublicLocal inspector") || !strings.Contains(string(b), "k7x.example") {
		t.Fatal("inspector page")
	}
	req, _ := http.NewRequest("GET", h.URL+"/api/requests", nil)
	req.Header.Set("Origin", "https://evil.example")
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin should be refused: %d", r.StatusCode)
	}
}

func TestBinaryBodies(t *testing.T) {
	s := NewStore(5)
	e := s.Add(client.Captured{Method: "POST", Path: "/", ReqBody: []byte{0, 1, 2, 255}, RespBody: []byte("fine")})
	if !e.ReqBinary || !strings.Contains(e.ReqBody, "binary") || e.RespBinary {
		t.Fatalf("binary detection: %+v", e)
	}
	if _, err := s.Replay(e.ID); err == nil {
		t.Fatal("binary bodies cannot be replayed")
	}
}
