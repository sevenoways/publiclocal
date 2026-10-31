package server

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrintable(t *testing.T) {
	cases := map[string]string{
		"/ok?a=b":      "/ok?a=b",
		"/x?\u009b31m": "/x??31m",  // C1 control (CSI)
		"/x?‮evil":     "/x??evil", // bidi override
		"/été":         "/été",     // ordinary accents survive
		"a\tb":         "a?b",
	}
	for in, want := range cases {
		if got := printable(in, 40); got != want {
			t.Errorf("printable(%q) = %q, want %q", in, got, want)
		}
	}
	if got := printable(strings.Repeat("é", 50), 10); got != strings.Repeat("é", 10)+"…" {
		t.Errorf("truncation splits runes or miscounts: %q", got)
	}
}

func TestSSHOutBounded(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	o := newSSHOut(stop)
	for i := range 1000 {
		o.say("line", string(rune('a'+i%26)))
	}
	if n := len(o.pending); n != maxPendingLines {
		t.Fatalf("pending grew to %d lines, want %d", n, maxPendingLines)
	}
}

func TestHostKeyNotReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	var warned []string
	warn := func(msg string, _ ...any) { warned = append(warned, msg) }
	k1, err := SSHHostKey(path, warn)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := SSHHostKey(path, warn)
	if err != nil || string(k1.PublicKey().Marshal()) != string(k2.PublicKey().Marshal()) {
		t.Fatalf("reloading changed the key: %v", err)
	}
	// A path that exists but cannot be read as a file must fail, not be overwritten.
	if _, err := SSHHostKey(dir, warn); err == nil {
		t.Fatal("unreadable key should be an error")
	}
	if b, _ := os.ReadFile(path); len(b) == 0 {
		t.Fatal("key file lost")
	}
}

func TestMuxSurvivesAcceptErrors(t *testing.T) {
	s := New(Config{Domain: "x.test"})
	fl := &flakyListener{errs: 3, inner: mustListen(t)}
	m := s.newSSHMux(fl)
	// Temporary accept errors must not end the listener.
	go func() {
		c, err := net.Dial("tcp", fl.inner.Addr().String())
		if err == nil {
			c.Write([]byte{0x16, 3, 1}) // looks like TLS
			time.Sleep(time.Second)
			c.Close()
		}
	}()
	done := make(chan error, 1)
	go func() {
		c, err := m.Accept()
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("accept after temporary errors: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mux stopped after accept errors")
	}
}

type flakyListener struct {
	errs  int
	inner net.Listener
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if f.errs > 0 {
		f.errs--
		return nil, &net.OpError{Op: "accept", Err: os.ErrDeadlineExceeded}
	}
	return f.inner.Accept()
}
func (f *flakyListener) Close() error   { return f.inner.Close() }
func (f *flakyListener) Addr() net.Addr { return f.inner.Addr() }

func mustListen(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}
