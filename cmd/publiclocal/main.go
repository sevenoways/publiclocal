// Command publiclocal is a self-hosted reverse tunnel: run `publiclocal server` on a public
// host, then `publiclocal http 3000` or `publiclocal tcp 22` anywhere to expose a local port.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/proto"
	"github.com/sevenoways/publiclocal/internal/server"
)

var version = "dev" // set by the release build

const usage = `publiclocal - self-hosted reverse tunnel

Usage:
  publiclocal server  --domain tunnel.example.com [flags]   run the public server
  publiclocal http    [flags] <port|host:port>              expose a local HTTP service
  publiclocal tcp     [flags] <port|host:port>              expose a local TCP service
  publiclocal version

Run "publiclocal <command> -h" for the flags of each command.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(ctx, os.Args[2:])
	case "http", "tcp":
		err = runClient(ctx, os.Args[1], os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("publiclocal", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "publiclocal: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "publiclocal:", err)
		os.Exit(1)
	}
}

func runServer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	domain := fs.String("domain", os.Getenv("PUBLICLOCAL_DOMAIN"), "base domain; tunnels are served at <name>.<domain> (env PUBLICLOCAL_DOMAIN)")
	control := fs.String("control", ":7000", "address for client connections")
	httpAddr := fs.String("http", ":80", "plain HTTP address (empty to disable)")
	httpsAddr := fs.String("https", ":443", "HTTPS address using Let's Encrypt (empty to disable)")
	tokens := fs.String("tokens", os.Getenv("PUBLICLOCAL_TOKENS"), "comma-separated tokens clients must present (env PUBLICLOCAL_TOKENS)")
	ports := fs.String("tcp-ports", "10000-20000", "port range for TCP tunnels")
	certDir := fs.String("cert-dir", "publiclocal-certs", "directory to cache TLS certificates")
	email := fs.String("acme-email", "", "contact email for Let's Encrypt")
	debug := fs.Bool("debug", false, "verbose logging")
	fs.Parse(args)

	if *domain == "" {
		return errors.New("--domain is required")
	}
	lo, hi, err := parseRange(*ports)
	if err != nil {
		return err
	}
	cfg := server.Config{
		Domain:      *domain,
		ControlAddr: *control,
		HTTPAddr:    *httpAddr,
		HTTPSAddr:   *httpsAddr,
		TCPPortMin:  lo,
		TCPPortMax:  hi,
		CertDir:     *certDir,
		ACMEEmail:   *email,
		Logger:      newLogger(*debug),
	}
	for t := range strings.SplitSeq(*tokens, ",") {
		if t = strings.TrimSpace(t); t != "" {
			cfg.Tokens = append(cfg.Tokens, t)
		}
	}
	return server.New(cfg).ListenAndServe(ctx)
}

func runClient(ctx context.Context, kind string, args []string) error {
	fs := flag.NewFlagSet(kind, flag.ExitOnError)
	srv := fs.String("server", os.Getenv("PUBLICLOCAL_SERVER"), "server control address host:port (env PUBLICLOCAL_SERVER)")
	token := fs.String("token", os.Getenv("PUBLICLOCAL_TOKEN"), "auth token (env PUBLICLOCAL_TOKEN)")
	useTLS := fs.Bool("tls", true, "use TLS to the server (turn off only for servers without HTTPS)")
	insecure := fs.Bool("insecure-skip-verify", false, "do not verify the server certificate")
	sub := fs.String("subdomain", "", "requested subdomain (http only)")
	remotePort := fs.Int("remote-port", 0, "requested public port (tcp only)")
	debug := fs.Bool("debug", false, "verbose logging")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: publiclocal %s [flags] <port|host:port>\n", kind)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	if *srv == "" {
		return errors.New("--server is required (or set PUBLICLOCAL_SERVER)")
	}
	local := fs.Arg(0)
	if _, err := strconv.Atoi(local); err == nil {
		local = "127.0.0.1:" + local
	}
	if !strings.Contains(*srv, ":") {
		*srv += ":7000"
	}
	t := client.Tunnel{Type: kind, Local: local}
	if kind == proto.TypeHTTP {
		t.Subdomain = *sub
	} else {
		t.RemotePort = *remotePort
	}
	log := newLogger(*debug)
	return client.Run(ctx, client.Config{
		Server:             *srv,
		Token:              *token,
		TLS:                *useTLS,
		InsecureSkipVerify: *insecure,
		Tunnels:            []client.Tunnel{t},
		Logger:             log,
		OnReady: func(infos []proto.TunnelInfo) {
			for _, i := range infos {
				fmt.Printf("Forwarding %s -> %s\n", i.URL, local)
			}
		},
	})
}

func parseRange(s string) (int, int, error) {
	a, b, ok := strings.Cut(s, "-")
	lo, err1 := strconv.Atoi(a)
	hi, err2 := strconv.Atoi(b)
	if !ok || err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
		return 0, 0, fmt.Errorf("invalid port range %q (want e.g. 10000-20000)", s)
	}
	return lo, hi, nil
}

func newLogger(debug bool) *slog.Logger {
	lvl := slog.LevelInfo
	if debug {
		lvl = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
