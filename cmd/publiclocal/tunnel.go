package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/inspect"
	"github.com/sevenoways/publiclocal/internal/proto"
)

// tunnelOpts are the flags shared by `http`, `tcp` and `share`.
type tunnelOpts struct {
	kind                    string
	server, token           *string
	useTLS, insecure        *bool
	sub, link               *string
	fresh, qr, quiet, cors  *bool
	password, note, inspect *string
	remotePort, maxVisits   *int
	expires                 *time.Duration
	debug                   *bool
}

func tunnelFlags(kind string) (*flag.FlagSet, *tunnelOpts) {
	fs := flag.NewFlagSet(kind, flag.ExitOnError)
	o := &tunnelOpts{kind: kind}
	if kind == "share" {
		o.kind = proto.TypeHTTP
	}
	o.server = fs.String("server", os.Getenv("PUBLICLOCAL_SERVER"), "server control address host:port (env PUBLICLOCAL_SERVER)")
	o.token = fs.String("token", os.Getenv("PUBLICLOCAL_TOKEN"), "auth token (env PUBLICLOCAL_TOKEN)")
	o.useTLS = fs.Bool("tls", true, "use TLS to the server (turn off only for servers without HTTPS)")
	o.insecure = fs.Bool("insecure-skip-verify", false, "do not verify the server certificate")
	o.fresh = fs.Bool("new", false, "get a new link instead of reusing the last one for this port")
	o.qr = fs.Bool("qr", false, "print a QR code of the link to scan with a phone")
	o.quiet = fs.Bool("quiet", false, "do not print each request as it is served")
	o.debug = fs.Bool("debug", false, "verbose logging")
	if kind == proto.TypeTCP {
		o.remotePort = fs.Int("remote-port", 0, "requested public port")
		return fs, o
	}
	o.sub = fs.String("subdomain", "", "requested subdomain (own server)")
	o.link = fs.String("link", "", "take back one of your links by name, e.g. k7xq2m (signed in)")
	o.password = fs.String("password", os.Getenv("PUBLICLOCAL_PASSWORD"), "visitors must enter this password, any user name (env PUBLICLOCAL_PASSWORD)")
	o.expires = fs.Duration("expires", 0, "shorter link lifetime, e.g. 30m or 2h")
	o.maxVisits = fs.Int("max-visits", 0, "only the first N people (networks) can use the link")
	o.note = fs.String("note", "", "a note shown to visitors on the link's first page, e.g. \"staging build for Anna\"")
	o.cors = fs.Bool("cors", false, "add permissive CORS headers so a browser app elsewhere can call this API")
	o.inspect = fs.String("inspect", "127.0.0.1:4040", "address of the local request inspector (empty to disable)")
	return fs, o
}

func runClient(ctx context.Context, kind string, args []string) error {
	fs, o := tunnelFlags(kind)
	fs.Usage = func() {
		if kind == proto.TypeHTTP {
			fmt.Fprintf(fs.Output(), "Usage: publiclocal http [flags] <port|host:port> [more ports...]\n")
		} else {
			fmt.Fprintf(fs.Output(), "Usage: publiclocal tcp [flags] <port|host:port>\n")
		}
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() < 1 || (kind == proto.TypeTCP && fs.NArg() != 1) {
		fs.Usage()
		os.Exit(2)
	}
	var locals []string
	for _, a := range fs.Args() {
		if _, err := strconv.Atoi(a); err == nil {
			a = "127.0.0.1:" + a
		}
		locals = append(locals, a)
	}
	return runTunnel(ctx, o, locals)
}

// runTunnel opens one tunnel per local address and keeps them up until ctx ends.
func runTunnel(ctx context.Context, o *tunnelOpts, locals []string) error {
	srv := resolveServer(*o.server)
	log := newLogger(*o.debug)
	account := accountFor(srv)
	if *o.useTLS == false && *o.token == "" && account != "" {
		fmt.Fprintln(os.Stderr, "warning: --tls=false sends your login token unencrypted")
	}

	tunnels := make([]client.Tunnel, len(locals))
	reusing := make([]bool, len(locals))
	for i, local := range locals {
		t := client.Tunnel{Type: o.kind, Local: local}
		if o.kind == proto.TypeTCP {
			t.RemotePort = *o.remotePort
		} else {
			t.Password, t.Note, t.MaxVisitors, t.MaxAge = *o.password, *o.note, *o.maxVisits, *o.expires
			if len(locals) == 1 {
				t.Subdomain = *o.sub
				if *o.link != "" {
					t.Subdomain = linkName(*o.link)
				}
			}
			if t.Subdomain == "" && !*o.fresh {
				if st := loadLink(linkKey(srv, local)); st != nil {
					t.Subdomain, t.Claim, reusing[i] = st.Name, st.Claim, true
				}
			}
		}
		tunnels[i] = t
	}

	// The request store feeds the terminal feed, the inspector and the summary.
	store := inspect.NewStore(500)
	var mu sync.Mutex
	var links []string
	inspectURL := ""
	if o.kind == proto.TypeHTTP && *o.inspect != "" {
		ln, err := net.Listen("tcp", *o.inspect)
		if err != nil { // port busy: pick a free one rather than fail
			ln, err = net.Listen("tcp", "127.0.0.1:0")
		}
		if err == nil {
			inspectURL = "http://" + ln.Addr().String()
			hs := &http.Server{Handler: store.Handler(func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), links...) })}
			go hs.Serve(ln)
			defer hs.Close()
		}
	}

	for {
		var last []string
		err := client.Run(ctx, client.Config{
			Server:             srv,
			Token:              *o.token,
			Account:            account,
			TLS:                *o.useTLS,
			InsecureSkipVerify: *o.insecure,
			Tunnels:            tunnels,
			Logger:             log,
			CORS:               o.kind == proto.TypeHTTP && *o.cors,
			CaptureBody:        captureBytes(inspectURL != ""),
			OnRequest: func(c client.Captured) {
				store.Add(c)
				if !*o.quiet {
					fmt.Printf("%s  %-6s %-40s %d  %4d ms  %s\n", c.Time.Format("15:04:05"), c.Method, clip(c.Path, 40), c.Status, c.Duration.Milliseconds(), c.Remote)
				}
			},
			OnReady: func(infos []proto.TunnelInfo) {
				same := len(last) == len(infos)
				var urls []string
				for i, info := range infos {
					urls = append(urls, info.URL)
					if same && last[i] != info.URL {
						same = false
					}
				}
				if same && last != nil {
					fmt.Println("Reconnected, same link")
					return
				}
				last = urls
				mu.Lock()
				links = urls
				mu.Unlock()
				for i, info := range infos {
					if info.Type == proto.TypeHTTP && info.Claim != "" {
						saveLink(linkKey(srv, locals[i]), storedLink{Name: info.Name, Claim: info.Claim, Expires: info.Expires})
					}
					fmt.Printf("Forwarding %s -> %s\n", info.URL, locals[i])
					if *o.qr {
						if q, err := qrcode.New(info.URL, qrcode.Medium); err == nil {
							fmt.Print("\n" + q.ToSmallString(false) + "\n")
						}
					}
					if reusing[i] && info.Name == tunnels[i].Subdomain {
						fmt.Println("Same link as last time; use --new for a different one")
					}
				}
				var notes []string
				if o.kind == proto.TypeHTTP && *o.password != "" {
					notes = append(notes, "password protected (any user name)")
				}
				if o.kind == proto.TypeHTTP && *o.maxVisits > 0 {
					notes = append(notes, fmt.Sprintf("first %d visitor(s) only", *o.maxVisits))
				}
				if o.kind == proto.TypeHTTP && *o.cors {
					notes = append(notes, "CORS headers on")
				}
				if len(notes) > 0 {
					fmt.Println("Link is " + strings.Join(notes, ", "))
				}
				if info := infos[0]; !info.Expires.IsZero() {
					hint := ""
					switch {
					case account == "":
						hint = "; run `publiclocal login` for 7-day links"
					case info.Type == proto.TypeHTTP && *o.expires == 0:
						hint = "; extend with `publiclocal extend " + info.Name + "`"
					}
					fmt.Printf("Link %s%s\n", expiryText(info.Expires), hint)
				}
				if inspectURL != "" {
					fmt.Printf("Inspector: %s (requests, headers, replay)\n", inspectURL)
				}
			},
		})
		var rej *client.RejectedError
		if errors.As(err, &rej) {
			if retry := false; true {
				for i := range tunnels {
					if reusing[i] {
						deleteLink(linkKey(srv, locals[i]))
						tunnels[i].Subdomain, tunnels[i].Claim, reusing[i] = "", "", false
						retry = true
					}
				}
				if retry {
					continue // the remembered link is gone; ask for a fresh one
				}
			}
		}
		printSummary(store)
		return err
	}
}

func captureBytes(inspector bool) int {
	if inspector {
		return inspect.MaxBody
	}
	return 0
}

func printSummary(store *inspect.Store) {
	s := store.Summary()
	if s.Requests == 0 {
		return
	}
	line := fmt.Sprintf("\nServed %d request%s from %d visitor%s · %s", s.Requests, plural(s.Requests), s.Visitors, plural(s.Visitors), humanSize(s.Bytes))
	if len(s.TopPaths) > 0 {
		line += " · top: " + strings.Join(s.TopPaths, ", ")
	}
	fmt.Println(line)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
