package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sevenoways/publiclocal/internal/inspect"
)

// runCatch opens a link that answers every request itself and keeps a copy,
// so webhooks can be set up before the app that handles them exists. The
// requests are saved to an inbox and can be replayed into the app later with
// `publiclocal replay --to 3000`.
func runCatch(ctx context.Context, args []string) error {
	fs, o := tunnelFlags("share")
	status := fs.Int("status", 200, "status code to answer with")
	body := fs.String("body", "ok", "response body to answer with")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: publiclocal catch [flags]")
		fmt.Fprintln(fs.Output(), "Answers every request with --status/--body and records it; replay later with `publiclocal replay --to <port>`.")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	if *status < 100 || *status > 599 {
		return errors.New("--status must be an HTTP status code")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, io.LimitReader(r.Body, 10<<20))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(*status)
		io.WriteString(w, *body)
	})}
	go srv.Serve(ln)
	defer srv.Close()

	dir, err := inboxDir()
	if err != nil {
		return err
	}
	o.inbox = filepath.Join(dir, time.Now().Format("20060102-150405")+".jsonl")
	fmt.Printf("Catching requests; they are saved to %s\n", o.inbox)
	fmt.Println("Replay them into your app later with: publiclocal replay --to 3000")
	return runTunnel(ctx, o, []string{ln.Addr().String()})
}

func inboxDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "publiclocal", "inbox")
	return dir, os.MkdirAll(dir, 0o700)
}

// runReplay sends requests saved by `catch` to a local app.
func runReplay(args []string) error {
	fs, _, _ := accountFlags("replay")
	to := fs.String("to", "", "local port or host:port to send the requests to (required)")
	file := fs.String("file", "", "inbox file to replay (default: the most recent)")
	id := fs.Int("id", 0, "replay only the request with this number")
	last := fs.Int("last", 0, "replay only the last N requests")
	list := fs.Bool("list", false, "list the saved requests instead of sending them")
	fs.Parse(args)
	if *to == "" && !*list {
		return errors.New("--to is required, e.g. --to 3000")
	}
	if _, err := strconv.Atoi(*to); err == nil {
		*to = "127.0.0.1:" + *to
	}
	path := *file
	if path == "" {
		dir, err := inboxDir()
		if err != nil {
			return err
		}
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".jsonl") {
				path = filepath.Join(dir, e.Name()) // names sort by time; keep the newest
			}
		}
		if path == "" {
			return errors.New("no saved requests yet; run `publiclocal catch` first")
		}
	}
	reqs, err := inspect.LoadInbox(path)
	if err != nil {
		return err
	}
	if *id > 0 {
		var one []*inspect.Entry
		for _, e := range reqs {
			if e.ID == *id {
				one = append(one, e)
			}
		}
		reqs = one
	}
	if *last > 0 && len(reqs) > *last {
		reqs = reqs[len(reqs)-*last:]
	}
	if len(reqs) == 0 {
		return errors.New("no matching requests in " + path)
	}
	for _, e := range reqs {
		if *list {
			fmt.Printf("#%-4d %s  %-6s %s\n", e.ID, e.Time.Local().Format("Jan 2 15:04:05"), e.Method, e.Path)
			continue
		}
		status, ms, err := inspect.Send(e, *to)
		if err != nil {
			fmt.Printf("#%-4d %-6s %-40s failed: %v\n", e.ID, e.Method, clip(e.Path, 40), err)
			continue
		}
		fmt.Printf("#%-4d %-6s %-40s %d  %d ms\n", e.ID, e.Method, clip(e.Path, 40), status, ms)
	}
	return nil
}

// copyToClipboard puts text on the system clipboard with the platform's tool.
func copyToClipboard(text string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("clip")
	case "darwin":
		cmd = exec.Command("pbcopy")
	default:
		if _, err := exec.LookPath("wl-copy"); err == nil {
			cmd = exec.Command("wl-copy")
		} else {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		}
	}
	cmd.Stdin = bytes.NewBufferString(text)
	return cmd.Run()
}
