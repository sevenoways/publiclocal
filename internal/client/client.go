// Package client connects to an publiclocal server and forwards tunnel traffic to
// local services, reconnecting when the connection drops.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/sevenoways/publiclocal/internal/pipe"
	"github.com/sevenoways/publiclocal/internal/proto"
)

type Tunnel struct {
	Type       string // proto.TypeHTTP or proto.TypeTCP
	Local      string // local address to forward to, e.g. "127.0.0.1:3000"
	Subdomain  string // HTTP only; empty for a random one
	RemotePort int    // TCP only; 0 for a random one

	// Claim takes back a link from an earlier run. The server returns it in
	// TunnelInfo; callers may store it to reuse a link across restarts.
	Claim string
}

type Config struct {
	Server             string // host:port of the server's control port
	Token              string // server access token (private servers)
	Account            string // login token from `publiclocal login`
	TLS                bool
	InsecureSkipVerify bool
	Tunnels            []Tunnel
	Logger             *slog.Logger

	// OnReady, if set, is called with the public URLs each time a session is established.
	OnReady func([]proto.TunnelInfo)
}

// RejectedError is returned when the server refuses the session (bad token,
// subdomain taken, ...). Retrying would not help, so Run gives up.
type RejectedError struct{ Reason string }

func (e *RejectedError) Error() string { return "server rejected session: " + e.Reason }

// Run keeps a session to the server open until ctx is cancelled or the server
// rejects the session.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cfg.Tunnels = slices.Clone(cfg.Tunnels) // runOnce records claims in it
	backoff := time.Second
	for {
		connected, err := runOnce(ctx, cfg)
		if ctx.Err() != nil {
			return nil
		}
		var rej *RejectedError
		if errors.As(err, &rej) {
			return err
		}
		if connected {
			backoff = time.Second
		}
		cfg.Logger.Warn("disconnected, retrying", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func runOnce(ctx context.Context, cfg Config) (connected bool, err error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var conn net.Conn
	if cfg.TLS {
		host, _, _ := net.SplitHostPort(cfg.Server)
		td := &tls.Dialer{NetDialer: d, Config: &tls.Config{ServerName: host, InsecureSkipVerify: cfg.InsecureSkipVerify}}
		conn, err = td.DialContext(ctx, "tcp", cfg.Server)
	} else {
		conn, err = d.DialContext(ctx, "tcp", cfg.Server)
	}
	if err != nil {
		return false, err
	}
	ycfg := yamux.DefaultConfig()
	ycfg.LogOutput = io.Discard
	ys, err := yamux.Client(conn, ycfg)
	if err != nil {
		conn.Close()
		return false, err
	}
	defer ys.Close()

	ctrl, err := ys.Open()
	if err != nil {
		return false, err
	}
	hello := proto.Hello{Version: proto.Version, Token: cfg.Token, Account: cfg.Account}
	for _, t := range cfg.Tunnels {
		hello.Tunnels = append(hello.Tunnels, proto.TunnelReq{Type: t.Type, Subdomain: t.Subdomain, RemotePort: t.RemotePort, Claim: t.Claim})
	}
	ctrl.SetDeadline(time.Now().Add(15 * time.Second))
	if err := proto.Write(ctrl, hello); err != nil {
		return false, err
	}
	var resp proto.HelloResp
	if err := proto.Read(ctrl, &resp); err != nil {
		return false, fmt.Errorf("handshake: %w", err)
	}
	if resp.Error != "" {
		return false, &RejectedError{resp.Error}
	}
	if len(resp.Tunnels) != len(cfg.Tunnels) {
		return false, errors.New("handshake: server returned wrong number of tunnels")
	}
	ctrl.SetDeadline(time.Time{})
	for i, info := range resp.Tunnels {
		if info.Claim != "" {
			cfg.Tunnels[i].Claim = info.Claim
			cfg.Tunnels[i].Subdomain = info.Name
		}
	}
	if cfg.OnReady != nil {
		cfg.OnReady(resp.Tunnels)
	}

	stop := context.AfterFunc(ctx, func() { ys.Close() })
	defer stop()
	for {
		st, err := ys.Accept()
		if err != nil {
			return true, err
		}
		go handleStream(st, cfg)
	}
}

func handleStream(st net.Conn, cfg Config) {
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	var h proto.StreamHeader
	if err := proto.Read(st, &h); err != nil || h.Tunnel < 0 || h.Tunnel >= len(cfg.Tunnels) {
		st.Close()
		return
	}
	st.SetReadDeadline(time.Time{})
	t := cfg.Tunnels[h.Tunnel]
	local, err := net.DialTimeout("tcp", t.Local, 10*time.Second)
	if err != nil {
		cfg.Logger.Warn("cannot reach local service", "addr", t.Local, "err", err)
		st.Close()
		return
	}
	pipe.Join(st, local)
}
