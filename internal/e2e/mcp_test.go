package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/sevenoways/publiclocal/internal/mcpserver"
)

func TestMCP(t *testing.T) {
	ctl, httpURL := startServer(t)
	app := webApp(t)
	_, port, _ := net.SplitHostPort(app)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	srvT, cliT := mcp.NewInMemoryTransports()
	s := mcpserver.New(ctx, mcpserver.Options{Server: ctl, AllowPorts: []int{atoi(port), 3000}})
	go s.Run(ctx, srvT)
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, cliT, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 3 {
		t.Fatalf("tools: %v %v", tools, err)
	}

	call := func(name string, args map[string]any) (map[string]any, bool) {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var out map[string]any
		b, _ := json.Marshal(res.StructuredContent)
		json.Unmarshal(b, &out)
		if res.IsError {
			return map[string]any{"error": res.Content[0].(*mcp.TextContent).Text}, true
		}
		return out, false
	}

	// Ports outside the allow list, and ports with nothing listening, are refused.
	if out, isErr := call("share_local_port", map[string]any{"port": 4444}); !isErr || !strings.Contains(out["error"].(string), "allowed") {
		t.Fatalf("disallowed port: %v", out)
	}
	if out, isErr := call("share_local_port", map[string]any{"port": 3000}); !isErr || !strings.Contains(out["error"].(string), "nothing is listening") {
		t.Fatalf("closed port: %v", out)
	}

	out, isErr := call("share_local_port", map[string]any{"port": atoi(port)})
	if isErr {
		t.Fatalf("share: %v", out)
	}
	id, pub := out["id"].(string), out["url"].(string)
	u, _ := url.Parse(pub)
	fetch := func() int {
		req, _ := http.NewRequest("GET", httpURL, nil)
		req.Host = u.Host
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := fetch(); code != 200 {
		t.Fatalf("tunnel via MCP: status %d", code)
	}

	list, _ := call("list_tunnels", nil)
	if n := len(list["tunnels"].([]any)); n != 1 {
		t.Fatalf("list: %v", list)
	}

	if out, isErr := call("stop_tunnel", map[string]any{"id": id}); isErr || out["stopped"] != true {
		t.Fatalf("stop: %v", out)
	}
	deadline := time.Now().Add(3 * time.Second)
	for fetch() != http.StatusServiceUnavailable && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if code := fetch(); code != http.StatusServiceUnavailable {
		t.Fatalf("stopped tunnel still answers: %d", code)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
