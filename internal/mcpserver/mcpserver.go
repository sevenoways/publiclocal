// Package mcpserver exposes PublicLocal to AI assistants over the Model Context
// Protocol. The assistant launches `publiclocal mcp` on the user's machine and
// can then share local ports, list the open tunnels and stop them. Tunnels
// live as long as the MCP server process.
package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sevenoways/publiclocal/internal/client"
	"github.com/sevenoways/publiclocal/internal/proto"
)

type Options struct {
	Server     string // host:port of the tunnel server
	Token      string
	Account    string // login token from `publiclocal login`
	TLS        bool
	AllowPorts []int // if set, only these local ports may be shared
	MaxTunnels int   // simultaneous tunnels; 0 means 5
	Version    string
	Logger     *slog.Logger // must not write to stdout, which carries the protocol
}

const instructions = `PublicLocal makes a port on this computer reachable from the internet through a public HTTPS link.
Use share_local_port when the user wants to share a local app, test webhooks or OAuth callbacks, or open their dev server on another device.
Sharing exposes the app to anyone with the link, so only share ports the user asked for, and tell the user the URL you get back.
On the free publiclocal.app server links last 24 hours (7 days if the user has run "publiclocal login"), names are random, browsers see a short notice first, and only HTTP is allowed.
Call stop_tunnel when the user is done.`

// Run serves MCP over stdin/stdout until the client disconnects or ctx ends,
// then closes every tunnel it opened.
func Run(ctx context.Context, opts Options) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	return New(ctx, opts).Run(ctx, &mcp.StdioTransport{})
}

// New builds the MCP server. Tunnels it opens close when ctx ends.
func New(ctx context.Context, opts Options) *mcp.Server {
	if opts.MaxTunnels == 0 {
		opts.MaxTunnels = 5
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.DiscardHandler)
	}
	m := &manager{ctx: ctx, opts: opts, tunnels: map[string]*tunnel{}}

	s := mcp.NewServer(&mcp.Implementation{Name: "publiclocal", Title: "PublicLocal", Version: opts.Version},
		&mcp.ServerOptions{Instructions: instructions})

	open := true
	mcp.AddTool(s, &mcp.Tool{
		Name:        "share_local_port",
		Description: "Make a port on this computer public. Returns a public URL that forwards to localhost:<port>. The local app must already be running.",
		Annotations: &mcp.ToolAnnotations{Title: "Share a local port", OpenWorldHint: &open},
	}, m.share)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_tunnels",
		Description: "List the tunnels opened in this session with their public URLs.",
		Annotations: &mcp.ToolAnnotations{Title: "List tunnels", ReadOnlyHint: true},
	}, m.list)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "stop_tunnel",
		Description: "Close a tunnel so its public URL stops working.",
		Annotations: &mcp.ToolAnnotations{Title: "Stop a tunnel", IdempotentHint: true},
	}, m.stop)
	return s
}

type manager struct {
	ctx     context.Context
	opts    Options
	mu      sync.Mutex
	tunnels map[string]*tunnel
	nextID  int
}

type tunnel struct {
	ID      string    `json:"id"`
	Kind    string    `json:"kind"`
	Port    int       `json:"port"`
	URL     string    `json:"url"`
	Created time.Time `json:"created"`
	cancel  context.CancelFunc
}

type ShareInput struct {
	Port      int    `json:"port" jsonschema:"local port the app listens on, e.g. 3000"`
	Kind      string `json:"kind,omitempty" jsonschema:"http (default) or tcp; tcp needs a self-hosted server"`
	Subdomain string `json:"subdomain,omitempty" jsonschema:"requested name; only on self-hosted servers, the public server assigns random names"`
	Password  string `json:"password,omitempty" jsonschema:"if set, visitors must enter this password (HTTP Basic auth, any user name) before reaching the app"`
}

type ShareOutput struct {
	ID      string    `json:"id" jsonschema:"tunnel id, for stop_tunnel"`
	URL     string    `json:"url" jsonschema:"public URL to give the user"`
	Expires time.Time `json:"expires,omitzero" jsonschema:"when the link stops working"`
	Note    string    `json:"note"`
}

func (m *manager) share(_ context.Context, _ *mcp.CallToolRequest, in ShareInput) (*mcp.CallToolResult, ShareOutput, error) {
	var out ShareOutput
	if in.Kind == "" {
		in.Kind = proto.TypeHTTP
	}
	if in.Kind != proto.TypeHTTP && in.Kind != proto.TypeTCP {
		return nil, out, fmt.Errorf("kind must be http or tcp")
	}
	if in.Port < 1 || in.Port > 65535 {
		return nil, out, fmt.Errorf("port must be between 1 and 65535")
	}
	if len(m.opts.AllowPorts) > 0 && !slices.Contains(m.opts.AllowPorts, in.Port) {
		return nil, out, fmt.Errorf("port %d is not in the allowed list %v (set with --allow-ports)", in.Port, m.opts.AllowPorts)
	}
	local := net.JoinHostPort("localhost", strconv.Itoa(in.Port))
	if c, err := net.DialTimeout("tcp", local, 2*time.Second); err != nil {
		return nil, out, fmt.Errorf("nothing is listening on localhost:%d; start the app first", in.Port)
	} else {
		c.Close()
	}

	m.mu.Lock()
	if len(m.tunnels) >= m.opts.MaxTunnels {
		m.mu.Unlock()
		return nil, out, fmt.Errorf("already %d tunnels open; stop one first", m.opts.MaxTunnels)
	}
	m.nextID++
	t := &tunnel{ID: "t" + strconv.Itoa(m.nextID), Kind: in.Kind, Port: in.Port, Created: time.Now()}
	m.mu.Unlock()

	// The tunnel outlives this tool call and lives as long as the server.
	tctx, cancel := context.WithCancel(m.ctx)
	t.cancel = cancel
	ready := make(chan proto.TunnelInfo, 1)
	done := make(chan error, 1)
	go func() {
		err := client.Run(tctx, client.Config{
			Server:  m.opts.Server,
			Token:   m.opts.Token,
			Account: m.opts.Account,
			TLS:     m.opts.TLS,
			Tunnels: []client.Tunnel{{Type: in.Kind, Local: local, Subdomain: in.Subdomain, Password: in.Password}},
			Logger:  m.opts.Logger,
			OnReady: func(infos []proto.TunnelInfo) {
				m.mu.Lock()
				t.URL = infos[0].URL // changes after a reconnect
				m.mu.Unlock()
				select {
				case ready <- infos[0]:
				default:
				}
			},
		})
		m.remove(t.ID)
		done <- err
	}()

	select {
	case info := <-ready:
		m.mu.Lock()
		m.tunnels[t.ID] = t
		m.mu.Unlock()
		out = ShareOutput{ID: t.ID, URL: info.URL, Expires: info.Expires, Note: "Share this URL with the user. It forwards to " + local + " until stop_tunnel is called, this session ends, or the link expires."}
		return nil, out, nil
	case err := <-done:
		cancel()
		var rej *client.RejectedError
		if errors.As(err, &rej) {
			return nil, out, errors.New(rej.Reason)
		}
		return nil, out, fmt.Errorf("could not open tunnel: %v", err)
	case <-time.After(20 * time.Second):
		cancel()
		return nil, out, fmt.Errorf("timed out connecting to %s", m.opts.Server)
	}
}

type ListOutput struct {
	Tunnels []*tunnel `json:"tunnels"`
}

func (m *manager) list(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, ListOutput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := ListOutput{Tunnels: []*tunnel{}}
	for _, t := range m.tunnels {
		c := *t
		out.Tunnels = append(out.Tunnels, &c)
	}
	slices.SortFunc(out.Tunnels, func(a, b *tunnel) int { return a.Created.Compare(b.Created) })
	return nil, out, nil
}

type StopInput struct {
	ID string `json:"id" jsonschema:"tunnel id from share_local_port or list_tunnels"`
}

type StopOutput struct {
	Stopped bool `json:"stopped"`
}

func (m *manager) stop(_ context.Context, _ *mcp.CallToolRequest, in StopInput) (*mcp.CallToolResult, StopOutput, error) {
	m.mu.Lock()
	t := m.tunnels[in.ID]
	delete(m.tunnels, in.ID)
	m.mu.Unlock()
	if t == nil {
		return nil, StopOutput{}, fmt.Errorf("no tunnel %q", in.ID)
	}
	t.cancel()
	return nil, StopOutput{Stopped: true}, nil
}

func (m *manager) remove(id string) {
	m.mu.Lock()
	delete(m.tunnels, id)
	m.mu.Unlock()
}
