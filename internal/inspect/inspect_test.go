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
	re, err := s.Replay(e.ID, "")
	if err != nil || re.ReplayOf != e.ID || re.Status != 200 || !strings.Contains(re.RespBody, `got POST {"id":1} host=k7xq2m.publiclocal.app`) {
		t.Fatalf("replay: %+v %v", re, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("app hit %d times", hits.Load())
	}
	if _, err := s.Replay(999, ""); err == nil {
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
	if r, _ := http.Get(h.URL + "/api/requests"); r.StatusCode != http.StatusForbidden {
		t.Fatalf("API without the token should be refused: %d", r.StatusCode)
	}
	areq, _ := http.NewRequest("GET", h.URL+"/api/requests", nil)
	areq.Header.Set("X-Inspector-Token", s.Token())
	resp, _ := http.DefaultClient.Do(areq)
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
	req.Header.Set("X-Inspector-Token", s.Token())
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin should be refused: %d", r.StatusCode)
	}
	// DNS rebinding: a foreign Host name is refused even with the token.
	req, _ = http.NewRequest("GET", h.URL+"/api/requests", nil)
	req.Host = "attacker.example"
	req.Header.Set("X-Inspector-Token", s.Token())
	if r, _ := http.DefaultClient.Do(req); r.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Host should be refused: %d", r.StatusCode)
	}
}

func TestLocalTarget(t *testing.T) {
	for _, bad := range []string{"127.0.0.1:80@evil.example", "evil.example:80", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:99999", "127.0.0.1:080", "10.0.0.1:80", "localhost:80/x"} {
		if _, ok := localTarget(bad); ok {
			t.Errorf("%q should be refused", bad)
		}
	}
	for _, good := range []string{"127.0.0.1:3000", "localhost:8080", "[::1]:3000"} {
		if _, ok := localTarget(good); !ok {
			t.Errorf("%q should be allowed", good)
		}
	}
}

func TestBinaryBodies(t *testing.T) {
	s := NewStore(5)
	e := s.Add(client.Captured{Method: "POST", Path: "/", ReqBody: []byte{0, 1, 2, 255}, RespBody: []byte("fine")})
	if !e.ReqBinary || !strings.Contains(e.ReqBody, "binary") || e.RespBinary {
		t.Fatalf("binary detection: %+v", e)
	}
	if _, err := s.Replay(e.ID, ""); err == nil {
		t.Fatal("binary bodies cannot be replayed")
	}
}

func TestInboxHARAndReplayTarget(t *testing.T) {
	path := t.TempDir() + "/inbox.jsonl"
	s := NewStore(10)
	if err := s.Persist(path); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Add(client.Captured{Time: time.Now(), Method: "POST", Path: "/hook?a=1", Host: "k.example", Status: 200,
		ReqHeader: http.Header{"Content-Type": {"application/json"}}, ReqBody: []byte(`{"n":1}`), RespHeader: http.Header{"Content-Type": {"text/plain"}}, RespBody: []byte("ok")})
	s.Add(client.Captured{Time: time.Now(), Method: "GET", Path: "/x", Host: "k.example", Status: 404})

	saved, err := LoadInbox(path)
	if err != nil || len(saved) != 2 || saved[0].ReqBody != `{"n":1}` {
		t.Fatalf("inbox: %d %v", len(saved), err)
	}

	var got []string
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.RequestURI()+" "+string(b))
		w.WriteHeader(201)
	}))
	defer app.Close()
	if status, _, err := Send(saved[0], app.Listener.Addr().String()); err != nil || status != 201 || got[0] != `POST /hook?a=1 {"n":1}` {
		t.Fatalf("send: %d %v %v", status, err, got)
	}
	// Replay never leaves this machine.
	if _, _, err := Send(saved[0], "203.0.113.5:80"); err == nil {
		t.Fatal("replay to a remote address should be refused")
	}
	if _, err := s.Replay(1, "example.com:80"); err == nil {
		t.Fatal("inspector replay to a remote address should be refused")
	}

	har := s.HAR()
	b, _ := json.Marshal(har)
	for _, want := range []string{`"version":"1.2"`, `"url":"https://k.example/hook?a=1"`, `"text":"{\"n\":1}"`, `"status":404`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("HAR missing %s: %s", want, b)
		}
	}
}
