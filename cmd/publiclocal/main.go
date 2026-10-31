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

	"github.com/sevenoways/publiclocal/internal/server"
)

var version = "dev" // set by the release build

// defaultServer is the free public instance, used when no server is given.
const defaultServer = "publiclocal.app:7000"

const usage = `publiclocal - make localhost public

Usage:
  publiclocal http    [flags] <port> [port...]              expose local HTTP services
  publiclocal share   [flags] <file or folder>              share a file or folder from this computer
  publiclocal tcp     [flags] <port|host:port>              expose a local TCP service (own server only)
  publiclocal login                                        sign in with GitHub for 7-day links
  publiclocal links                                         your links and when they expire
  publiclocal extend  <link>                                give a link another 7 days
  publiclocal logout
  publiclocal mcp     [flags]                               MCP server for AI assistants (Claude, Cursor, Codex...)
  publiclocal server  --domain tunnel.example.com [flags]   run your own server
  publiclocal admin   list | links | forget <sub> | suspend <sub> | kill <sub|ip> | ban <ip> | flags | scan
  publiclocal version

Without --server (or PUBLICLOCAL_SERVER) clients use the free public server
at publiclocal.app. Links there last 24 hours, or 7 days when signed in.

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
	case "share":
		err = runShare(ctx, os.Args[2:])
	case "admin":
		err = runAdmin(os.Args[2:])
	case "mcp":
		err = runMCP(ctx, os.Args[2:])
	case "login":
		err = runLogin(ctx, os.Args[2:])
	case "logout":
		err = runLogout(os.Args[2:])
	case "links":
		err = runLinks(os.Args[2:])
	case "extend":
		err = runExtend(os.Args[2:])
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
	cfToken := fs.String("cloudflare-token", os.Getenv("CLOUDFLARE_DNS_API_TOKEN"), "Cloudflare API token (DNS edit) for one wildcard certificate (env CLOUDFLARE_DNS_API_TOKEN)")
	admin := fs.String("admin", "127.0.0.1:7001", "admin API address, keep it on localhost (empty to disable)")
	public := fs.Bool("public", false, "run as an open public instance: random subdomains only, no TCP, warning page, limits")
	warning := fs.Bool("warning", false, "show the browser warning page (always on with --public)")
	abuse := fs.String("abuse-contact", "", "mailto: or https: link for abuse reports, shown on the warning page")
	maxAge := fs.Duration("max-tunnel-age", 0, "links expire this long after creation, e.g. 24h (public default 24h; 0 = never)")
	accountAge := fs.Duration("account-tunnel-age", 0, "link lifetime for signed-in users and per `extend` (public default 168h)")
	stateFile := fs.String("state-file", "", "file that keeps links and accounts across restarts")
	ghID := fs.String("github-client-id", os.Getenv("GITHUB_CLIENT_ID"), "GitHub OAuth app client ID; enables `publiclocal login` (env GITHUB_CLIENT_ID)")
	ghSecret := fs.String("github-client-secret", os.Getenv("GITHUB_CLIENT_SECRET"), "GitHub OAuth app client secret (env GITHUB_CLIENT_SECRET)")
	scanEvery := fs.Duration("scan-interval", 0, "check random live links for phishing this often (public default 10m)")
	linksPerIP := fs.Int("max-links-per-ip", 0, "active links per client network, IPv4 address or IPv6 /64 (public default 10)")
	linksPerAcct := fs.Int("max-links-per-account", 0, "active links per signed-in account (public default 50)")
	connRate := fs.Int("connects-per-minute", 0, "client connections per network per minute (public default 30)")
	adminToken := fs.String("admin-token", os.Getenv("PUBLICLOCAL_ADMIN_TOKEN"), "bearer token the admin API requires (env PUBLICLOCAL_ADMIN_TOKEN)")
	perIP := fs.Int("max-per-ip", 0, "max simultaneous sessions per client IP (public default 3)")
	rpm := fs.Int("rate", 0, "max requests per minute per HTTP tunnel (public default 600)")
	maxMB := fs.Int64("max-transfer-mb", 0, "max traffic per session in MB (public default 2048)")
	banFile := fs.String("ban-file", "", "file of banned client IPs, one per line")
	siteDir := fs.String("site-dir", "", "static files to serve as the homepage on the bare domain")
	sshAddr := fs.String("ssh", "", "also accept SSH tunnels (ssh -R0:localhost:3000 <domain>) on this address, e.g. :2222")
	sshOnHTTPS := fs.Bool("ssh-on-https", false, "also accept SSH tunnels on the HTTPS port, so `ssh -p 443` works through firewalls")
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
		Domain:             *domain,
		ControlAddr:        *control,
		HTTPAddr:           *httpAddr,
		HTTPSAddr:          *httpsAddr,
		TCPPortMin:         lo,
		TCPPortMax:         hi,
		CertDir:            *certDir,
		ACMEEmail:          *email,
		CloudflareToken:    *cfToken,
		AdminAddr:          *admin,
		Public:             *public,
		Warning:            *warning,
		AbuseContact:       *abuse,
		MaxTunnelAge:       *maxAge,
		AccountTunnelAge:   *accountAge,
		StateFile:          *stateFile,
		GitHubClientID:     *ghID,
		GitHubClientSecret: *ghSecret,
		ScanInterval:       *scanEvery,
		MaxLinksPerIP:      *linksPerIP,
		MaxLinksPerAccount: *linksPerAcct,
		ConnectsPerMinute:  *connRate,
		AdminToken:         *adminToken,
		MaxSessionsPerIP:   *perIP,
		RequestsPerMinute:  *rpm,
		MaxBytesPerSession: *maxMB << 20,
		BanFile:            *banFile,
		SiteDir:            *siteDir,
		SSHAddr:            *sshAddr,
		SSHOnHTTPS:         *sshOnHTTPS,
		Logger:             newLogger(*debug),
	}
	if *public && *abuse == "" {
		return errors.New("--public needs --abuse-contact so visitors can report misuse")
	}
	for t := range strings.SplitSeq(*tokens, ",") {
		if t = strings.TrimSpace(t); t != "" {
			cfg.Tokens = append(cfg.Tokens, t)
		}
	}
	return server.New(cfg).ListenAndServe(ctx)
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
