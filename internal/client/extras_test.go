package client

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sign(secret, msg string) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func TestVerifiers(t *testing.T) {
	now := time.Now()
	ts := strconv.FormatInt(now.Unix(), 10)
	old := strconv.FormatInt(now.Add(-time.Hour).Unix(), 10)
	body := []byte(`{"id":"evt_1"}`)
	cases := []struct {
		provider string
		hdr      http.Header
		want     string
	}{
		{"stripe", http.Header{"Stripe-Signature": {"t=" + ts + ",v1=" + hex.EncodeToString(sign("whsec", ts+"."+string(body)))}}, "valid"},
		{"stripe", http.Header{"Stripe-Signature": {"t=" + old + ",v1=" + hex.EncodeToString(sign("whsec", old+"."+string(body)))}}, "signature too old (replayed?)"},
		{"stripe", http.Header{"Stripe-Signature": {"t=" + ts + ",v1=" + hex.EncodeToString(sign("other", ts+"."+string(body)))}}, "bad signature (wrong secret, or body changed)"},
		{"stripe", http.Header{}, "no Stripe-Signature header"},
		{"github", http.Header{"X-Hub-Signature-256": {"sha256=" + hex.EncodeToString(sign("whsec", string(body)))}}, "valid"},
		{"github", http.Header{"X-Hub-Signature-256": {"sha256=00"}}, "bad signature (wrong secret, or body changed)"},
		{"slack", http.Header{"X-Slack-Signature": {"v0=" + hex.EncodeToString(sign("whsec", "v0:"+ts+":"+string(body)))}, "X-Slack-Request-Timestamp": {ts}}, "valid"},
		{"shopify", http.Header{"X-Shopify-Hmac-Sha256": {base64.StdEncoding.EncodeToString(sign("whsec", string(body)))}}, "valid"},
		{"shopify", http.Header{"X-Shopify-Hmac-Sha256": {base64.StdEncoding.EncodeToString(sign("x", string(body)))}}, "bad signature (wrong secret, or body changed)"},
	}
	for _, c := range cases {
		v, err := ParseVerifier(c.provider + ":whsec")
		if err != nil {
			t.Fatal(err)
		}
		if got := v.Check(c.hdr, body, now); got != c.want {
			t.Errorf("%s %v: got %q, want %q", c.provider, c.hdr, got, c.want)
		}
	}
	for _, bad := range []string{"stripe", "paypal:x", ":x"} {
		if _, err := ParseVerifier(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestParsers(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "users.json")
	os.WriteFile(f, []byte(`[]`), 0o600)
	m, err := ParseMock("POST /api/*=201:" + f)
	if err != nil || m.Method != "POST" || !m.Prefix || m.Path != "/api/" || m.Status != 201 || m.File != f {
		t.Fatalf("mock: %+v %v", m, err)
	}
	if m, err := ParseMock("/gone=404"); err != nil || m.Status != 404 || m.File != "" {
		t.Fatalf("status mock: %+v %v", m, err)
	}
	for _, bad := range []string{"/x", "x=" + f, "/x=/no/such/file"} {
		if _, err := ParseMock(bad); err == nil {
			t.Errorf("mock %q should be refused", bad)
		}
	}
	if lo, hi, err := ParseLatency("200ms-1s"); err != nil || lo != 200*time.Millisecond || hi != time.Second {
		t.Fatalf("latency range: %v %v %v", lo, hi, err)
	}
	for _, bad := range []string{"fast", "1s-200ms", "2m", "-1s"} {
		if _, _, err := ParseLatency(bad); err == nil {
			t.Errorf("latency %q should be refused", bad)
		}
	}
	if f, err := ParseFailRate("10%"); err != nil || f != 0.1 {
		t.Fatalf("fail: %v %v", f, err)
	}
	if _, err := ParseFailRate("150%"); err == nil {
		t.Error("fail 150% should be refused")
	}
}

func TestCleanText(t *testing.T) {
	in := "hi\x1b[2J\x1b]0;pwned\x07 there‮\nline2"
	got := cleanText(in, 100, true)
	if strings.ContainsAny(got, "\x1b\x07‮") || !strings.Contains(got, "\nline2") {
		t.Fatalf("control characters kept: %q", got)
	}
	if got := cleanText("a\nb", 100, false); got != "a b" {
		t.Fatalf("single line: %q", got)
	}
	if got := cleanText(strings.Repeat("é", 50), 10, false); len([]rune(got)) != 10 {
		t.Fatalf("trim: %q", got)
	}
}

func TestInjectWidget(t *testing.T) {
	mk := func(ct, enc, body string) *http.Response {
		r := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {ct}}, Body: io.NopCloser(strings.NewReader(body)), Request: &http.Request{Method: "GET"}, ContentLength: int64(len(body))}
		if enc != "" {
			r.Header.Set("Content-Encoding", enc)
		}
		return r
	}
	r := mk("text/html; charset=utf-8", "", "<html><body>x</BODY></html>")
	injectWidget(r)
	b, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(b), `<script src="/.publiclocal/feedback.js" defer></script></BODY>`) || r.Header.Get("Content-Length") != strconv.Itoa(len(b)) {
		t.Fatalf("not injected: %q", b)
	}
	for _, r := range []*http.Response{mk("application/json", "", "{}"), mk("text/html", "gzip", "zz")} {
		before := r.ContentLength
		injectWidget(r)
		if b, _ := io.ReadAll(r.Body); int64(len(b)) != before {
			t.Fatalf("changed a non-HTML or compressed body: %q", b)
		}
	}
}

func TestReviewFixes(t *testing.T) {
	if _, err := ParseMock("/x=204:" + os.Args[0]); err == nil {
		t.Error("204 with a body should be refused")
	}
	m, _ := ParseMock("/api/users=404")
	for _, p := range []string{"/api/users", "//api/users", "/api/./users"} {
		if !m.matches(&http.Request{Method: "GET", URL: &url.URL{Path: p}}) {
			t.Errorf("%s should match", p)
		}
	}
	v := &Verifier{Provider: "github", Secret: "s"}
	if got := v.verifyRequest(&http.Request{Method: "GET", Header: http.Header{}}); got != "" {
		t.Errorf("GET should not be checked: %q", got)
	}
	if got := cleanText("a\u200bb\ufeffc", 10, false); got != "a b c" {
		t.Errorf("format characters kept: %q", got)
	}
	r := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader("<body></body>")), Request: &http.Request{Method: "GET"}, ContentLength: -1}
	injectWidget(r)
	if b, _ := io.ReadAll(r.Body); string(b) != "<body></body>" {
		t.Errorf("streamed page changed: %q", b)
	}
}
