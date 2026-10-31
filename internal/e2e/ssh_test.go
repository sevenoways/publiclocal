package e2e

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sevenoways/publiclocal/internal/server"
)

// startSSH runs a public server with SSH tunnels enabled and returns it with
// its SSH address and HTTP URL.
func startSSH(t *testing.T, cfg server.Config) (*server.Server, string, string) {
	t.Helper()
	cfg.Domain = domain
	cfg.Public = true
	cfg.AbuseContact = "mailto:abuse@example.com"
	cfg.SSHHostKeyFile = filepath.Join(t.TempDir(), "hostkey")
	cfg.Logger = slog.New(slog.DiscardHandler)
	srv := server.New(cfg)
	if _, err := srv.EnableSSH(); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go srv.ServeSSH(ln)
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	return srv, ln.Addr().String(), hs.URL
}

// sshTunnel connects like `ssh -R0:<app>` would and returns the public link
// printed in the SSH window, plus a reader for the rest of that window.
func sshTunnel(t *testing.T, conn net.Conn, app http.Handler) (string, *bufio.Reader, *ssh.Client) {
	t.Helper()
	cc, chans, reqs, err := ssh.NewClientConn(conn, "publiclocal", &ssh.ClientConfig{User: "anyone", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	cl := ssh.NewClient(cc, chans, reqs)
	t.Cleanup(func() { cl.Close() })
	ln, err := cl.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("remote forward: %v", err)
	}
	go http.Serve(ln, app)
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(out)
	re := regexp.MustCompile(`Forwarding\s+(http\S+)`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		line, err := br.ReadString('\n')
		if m := re.FindStringSubmatch(line); m != nil {
			return m[1], br, cl
		}
		if err != nil {
			t.Fatalf("ssh window closed before a link was shown: %v", err)
		}
	}
	t.Fatal("no link shown")
	return "", nil, nil
}

func TestSSHTunnel(t *testing.T) {
	srv, sshAddr, httpURL := startSSH(t, server.Config{})
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "via ssh host=%s xfp=%s", r.Host, r.Header.Get("X-Forwarded-Proto"))
	})
	c, err := net.Dial("tcp", sshAddr)
	if err != nil {
		t.Fatal(err)
	}
	link, window, cl := sshTunnel(t, c, app)
	u, _ := url.Parse(link)
	q := tunnelReq{t, httpURL, u.Host}

	if _, body := q.do("GET", "/hello", nil, ""); body != "via ssh host="+u.Host+" xfp=http" {
		t.Fatalf("through the ssh tunnel: %q", body)
	}
	// Browsers still get the warning page first.
	if _, body := q.do("GET", "/", browserHdr, ""); !strings.Contains(body, "temporary developer link") {
		t.Fatal("warning page missing for ssh links")
	}
	// The request shows up in the SSH window.
	found := make(chan bool, 1)
	go func() {
		for {
			line, err := window.ReadString('\n')
			if strings.Contains(line, "/hello") {
				found <- true
				return
			}
			if err != nil {
				found <- false
				return
			}
		}
	}()
	select {
	case ok := <-found:
		if !ok {
			t.Fatal("request feed missing")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request not shown in the ssh window")
	}

	// Disconnecting ends the link and frees its place; the page says it expired.
	cl.Close()
	deadline := time.Now().Add(3 * time.Second)
	for len(srv.Links()) != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := len(srv.Links()); n != 0 {
		t.Fatalf("ssh link should end with the connection, %d left", n)
	}
	if resp, body := q.do("GET", "/", browserHdr, ""); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Live from") {
		t.Fatalf("after disconnect: %d", resp.StatusCode)
	}
}

func TestSSHLimitsAndRefusals(t *testing.T) {
	srv, sshAddr, _ := startSSH(t, server.Config{MaxSessionsPerIP: 1})
	c, _ := net.Dial("tcp", sshAddr)
	sshTunnel(t, c, http.NotFoundHandler())

	// A second session from the same network is refused with a message.
	c2, _ := net.Dial("tcp", sshAddr)
	cc, chans, reqs, err := ssh.NewClientConn(c2, "publiclocal", &ssh.ClientConfig{User: "x", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	cl := ssh.NewClient(cc, chans, reqs)
	defer cl.Close()
	sess, err := cl.NewSession()
	if err == nil {
		out, _ := sess.StdoutPipe()
		sess.Shell()
		b, _ := io.ReadAll(out)
		if !strings.Contains(string(b), "too many tunnels") {
			t.Fatalf("refusal message: %q", b)
		}
	}
	// Local port forwarding (-L) is not offered.
	if _, err := cl.Dial("tcp", "127.0.0.1:22"); err == nil {
		t.Fatal("direct-tcpip should be refused")
	}
	_ = srv
}

// TestSSHOnHTTPSPort checks that one port serves both TLS and SSH.
func TestSSHOnHTTPSPort(t *testing.T) {
	cfg := server.Config{Domain: domain, Public: true, AbuseContact: "mailto:a@b.c", Logger: slog.New(slog.DiscardHandler), SSHHostKeyFile: filepath.Join(t.TempDir(), "k")}
	srv := server.New(cfg)
	if _, err := srv.EnableSSH(); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(srv)
	ts.Listener.Close()
	ts.Listener = srv.SSHMuxForTest(ln)
	ts.StartTLS()
	defer ts.Close()

	// HTTPS still works on the port.
	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("https through the mux: %v", err)
	}
	resp.Body.Close()
	// And an SSH client on the same port gets a tunnel.
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	link, _, _ := sshTunnel(t, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "mux ok") }))
	u, _ := url.Parse(link)
	req, _ := http.NewRequest("GET", ts.URL+"/", nil)
	req.Host = u.Host
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != "mux ok" {
		t.Fatalf("tunnel over https port: %q", b)
	}
	_ = tls.VersionTLS12
}

// TestSSHAbuseLimits covers the review findings that a hostile SSH client
// could otherwise use: unlimited forwards and extra session channels.
func TestSSHAbuseLimits(t *testing.T) {
	_, sshAddr, _ := startSSH(t, server.Config{MaxLinksPerIP: 100})
	c, err := net.Dial("tcp", sshAddr)
	if err != nil {
		t.Fatal(err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(c, "publiclocal", &ssh.ClientConfig{User: "x", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	cl := ssh.NewClient(cc, chans, reqs)
	defer cl.Close()

	ok := 0
	for range 30 {
		payload := ssh.Marshal(struct {
			Addr string
			Port uint32
		}{"localhost", 0})
		if accepted, _, err := cl.SendRequest("tcpip-forward", true, payload); err == nil && accepted {
			ok++
		}
	}
	if ok != 16 {
		t.Fatalf("forwards accepted: %d, want 16", ok)
	}
	if _, err := cl.NewSession(); err != nil {
		t.Fatalf("first session: %v", err)
	}
	if _, err := cl.NewSession(); err == nil {
		t.Fatal("a second session channel should be refused")
	}
	// cancel-tcpip-forward is refused honestly.
	if accepted, _, _ := cl.SendRequest("cancel-tcpip-forward", true, ssh.Marshal(struct {
		Addr string
		Port uint32
	}{"localhost", 80})); accepted {
		t.Fatal("cancel should not claim success")
	}
}
