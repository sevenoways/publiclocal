package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Login tokens are stored per server, so signing in to publiclocal.app and to
// a self-hosted server can coexist.
func credentialsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "publiclocal", "credentials.json"), nil
}

func loadCredentials() map[string]string {
	creds := map[string]string{}
	if p, err := credentialsPath(); err == nil {
		if b, err := os.ReadFile(p); err == nil {
			json.Unmarshal(b, &creds)
		}
	}
	return creds
}

func saveCredentials(creds map[string]string) error {
	p, err := credentialsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(creds, "", "  ")
	return os.WriteFile(p, b, 0o600)
}

// serverHost is the host part of a control address like "publiclocal.app:7000".
func serverHost(server string) string {
	if h, _, err := net.SplitHostPort(server); err == nil {
		return h
	}
	return server
}

// accountFor returns the stored login token for a server, if any.
func accountFor(server string) string {
	if t := os.Getenv("PUBLICLOCAL_ACCOUNT"); t != "" {
		return t
	}
	return loadCredentials()[serverHost(server)]
}

type apiClient struct {
	base  string
	token string
}

func newAPI(server string, useTLS bool) *apiClient {
	scheme := "https"
	if !useTLS {
		scheme = "http"
	}
	return &apiClient{base: scheme + "://" + serverHost(server), token: accountFor(server)}
}

func (a *apiClient) call(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, a.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct{ Error string }
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	if out != nil {
		return json.Unmarshal(b, out)
	}
	return nil
}

func accountFlags(name string) (*flag.FlagSet, *string, *bool) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	srv := fs.String("server", os.Getenv("PUBLICLOCAL_SERVER"), "server (env PUBLICLOCAL_SERVER; default publiclocal.app)")
	useTLS := fs.Bool("tls", true, "use HTTPS to reach the server")
	return fs, srv, useTLS
}

func resolveServer(s string) string {
	if s == "" {
		s = defaultServer
	}
	if !strings.Contains(s, ":") {
		s += ":7000"
	}
	return s
}

func runLogin(ctx context.Context, args []string) error {
	fs, srv, useTLS := accountFlags("login")
	fs.Parse(args)
	server := resolveServer(*srv)
	api := newAPI(server, *useTLS)
	api.token = ""

	if !*useTLS {
		fmt.Fprintln(os.Stderr, "warning: --tls=false sends your login token unencrypted")
	}
	var start struct{ ID, Secret, Code string }
	if err := api.call("POST", "/api/login/start", nil, &start); err != nil {
		return fmt.Errorf("cannot start login: %w", err)
	}
	// Build the page address here rather than trusting one from the server.
	loginURL := api.base + "/login?id=" + url.QueryEscape(start.ID)
	fmt.Printf("Sign in with GitHub to get 7-day links you can extend.\n\n")
	fmt.Printf("  1. Open   %s\n  2. Enter  %s\n\n", loginURL, start.Code)
	openBrowser(loginURL)
	fmt.Println("Waiting for you to finish in the browser...")

	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(2 * time.Second):
		}
		var poll struct{ Status, Token, Login string }
		if err := api.call("POST", "/api/login/poll", map[string]string{"id": start.ID, "secret": start.Secret}, &poll); err != nil {
			return err
		}
		if poll.Status == "ok" {
			creds := loadCredentials()
			creds[serverHost(server)] = poll.Token
			if err := saveCredentials(creds); err != nil {
				return fmt.Errorf("signed in, but could not save the login: %w", err)
			}
			fmt.Printf("Signed in as %s. New links now last 7 days; extend them with `publiclocal extend <link>`.\n", poll.Login)
			return nil
		}
	}
	return errors.New("login timed out; run publiclocal login again")
}

func runLogout(args []string) error {
	fs, srv, useTLS := accountFlags("logout")
	fs.Parse(args)
	host := serverHost(resolveServer(*srv))
	if api := newAPI(resolveServer(*srv), *useTLS); api.token != "" {
		api.call("POST", "/api/logout", nil, nil) // revoke server-side; best effort
	}
	creds := loadCredentials()
	delete(creds, host)
	if err := saveCredentials(creds); err != nil {
		return err
	}
	fmt.Println("Signed out of", host)
	return nil
}

func runLinks(args []string) error {
	fs, srv, useTLS := accountFlags("links")
	fs.Parse(args)
	api := newAPI(resolveServer(*srv), *useTLS)
	if api.token == "" {
		return errors.New("not signed in; run publiclocal login")
	}
	var me struct {
		Login string
		Links []struct {
			URL     string
			Expires time.Time
			Online  bool
		}
	}
	if err := api.call("GET", "/api/me", nil, &me); err != nil {
		return err
	}
	fmt.Println("Signed in as", me.Login)
	if len(me.Links) == 0 {
		fmt.Println("No active links.")
	}
	for _, l := range me.Links {
		state := "offline"
		if l.Online {
			state = "online"
		}
		fmt.Printf("  %-40s %-8s %s\n", l.URL, state, expiryText(l.Expires))
	}
	return nil
}

func runExtend(args []string) error {
	fs, srv, useTLS := accountFlags("extend")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: publiclocal extend <link or name>")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	api := newAPI(resolveServer(*srv), *useTLS)
	if api.token == "" {
		return errors.New("only signed-in users can extend links; run publiclocal login")
	}
	var out struct {
		URL     string
		Expires time.Time
	}
	if err := api.call("POST", "/api/extend", map[string]string{"name": linkName(fs.Arg(0))}, &out); err != nil {
		return err
	}
	fmt.Printf("%s now %s\n", out.URL, expiryText(out.Expires))
	return nil
}

// linkName accepts "k7xq2m", "k7xq2m.publiclocal.app" or a full URL.
func linkName(s string) string {
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		s = u.Hostname()
	}
	name, _, _ := strings.Cut(s, ".")
	return strings.ToLower(name)
}

func expiryText(t time.Time) string {
	if t.IsZero() {
		return "does not expire"
	}
	d := time.Until(t).Round(time.Minute)
	when := t.Local().Format("Mon 2 Jan 15:04")
	switch {
	case d <= 0:
		return "has expired"
	case d >= 48*time.Hour:
		return fmt.Sprintf("expires in %d days (%s)", int((d+12*time.Hour).Hours()/24), when)
	case d >= 2*time.Hour:
		return fmt.Sprintf("expires in %d hours (%s)", int((d + 30*time.Minute).Hours()), when)
	default:
		return fmt.Sprintf("expires in %d minutes (%s)", int(d.Minutes()), when)
	}
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	cmd.Start()
}
