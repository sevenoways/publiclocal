package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/sevenoways/publiclocal/internal/mcpserver"
)

// runMCP serves the Model Context Protocol on stdin/stdout, so AI assistants
// can open and close tunnels on this machine.
func runMCP(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	srv := fs.String("server", os.Getenv("PUBLICLOCAL_SERVER"), "server control address (env PUBLICLOCAL_SERVER; default the free publiclocal.app server)")
	token := fs.String("token", os.Getenv("PUBLICLOCAL_TOKEN"), "auth token (env PUBLICLOCAL_TOKEN)")
	useTLS := fs.Bool("tls", true, "use TLS to the server")
	allow := fs.String("allow-ports", os.Getenv("PUBLICLOCAL_ALLOW_PORTS"), "comma-separated local ports the assistant may share; empty allows any (env PUBLICLOCAL_ALLOW_PORTS)")
	maxTunnels := fs.Int("max-tunnels", 5, "max tunnels open at once")
	debug := fs.Bool("debug", false, "log to stderr")
	fs.Parse(args)

	if *srv == "" {
		*srv = defaultServer
	}
	if !strings.Contains(*srv, ":") {
		*srv += ":7000"
	}
	var ports []int
	for p := range strings.SplitSeq(*allow, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("invalid port %q in --allow-ports", p)
		}
		ports = append(ports, n)
	}
	// stdout carries the protocol, so logs go to stderr (and only with --debug).
	log := slog.New(slog.DiscardHandler)
	if *debug {
		log = newLogger(true)
	}
	return mcpserver.Run(ctx, mcpserver.Options{
		Server:     *srv,
		Token:      *token,
		Account:    accountFor(*srv),
		TLS:        *useTLS,
		AllowPorts: ports,
		MaxTunnels: *maxTunnels,
		Version:    version,
		Logger:     log,
	})
}
