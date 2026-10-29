# Use PublicLocal from AI assistants (MCP)

`publiclocal mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server. Add it to your AI assistant and you can say things like *"share my dev server on port 3000"* or *"give me a public URL for the Stripe webhook"*. The assistant opens the tunnel on your machine and gives you the link.

It runs locally, launched by the assistant, because the tunnel has to start on the computer where your app runs.

## Tools

| Tool | What it does |
|---|---|
| `share_local_port` | Opens a tunnel to `localhost:<port>` and returns the public URL. Checks first that something is listening. |
| `list_tunnels` | Lists the tunnels opened in this session. |
| `stop_tunnel` | Closes a tunnel. All tunnels also close when the assistant session ends. |

## Setup

Install PublicLocal first so `publiclocal` is on your PATH:

```bash
curl -fsSL https://publiclocal.app/install.sh | sh
```

On Windows, download the zip from [Releases](https://github.com/sevenoways/publiclocal/releases/latest) and put `publiclocal.exe` in a folder on your PATH, or use the full path below.

### Claude Code

```bash
claude mcp add publiclocal -- publiclocal mcp
```

### Claude Desktop

*Settings → Developer → Edit Config*, then add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "publiclocal": { "command": "publiclocal", "args": ["mcp"] }
  }
}
```

### Cursor

`~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one project):

```json
{
  "mcpServers": {
    "publiclocal": { "command": "publiclocal", "args": ["mcp"] }
  }
}
```

### VS Code (GitHub Copilot agent mode)

`.vscode/mcp.json`:

```json
{
  "servers": {
    "publiclocal": { "type": "stdio", "command": "publiclocal", "args": ["mcp"] }
  }
}
```

### OpenAI Codex CLI

```bash
codex mcp add publiclocal -- publiclocal mcp
```

or in `~/.codex/config.toml`:

```toml
[mcp_servers.publiclocal]
command = "publiclocal"
args = ["mcp"]
```

### Gemini CLI

`~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "publiclocal": { "command": "publiclocal", "args": ["mcp"] }
  }
}
```

### ChatGPT (web and desktop app)

ChatGPT connects only to **remote** MCP servers on the internet. It can't launch programs on your computer, so it can't open a tunnel to your machine. Use the **Codex CLI** (above) for OpenAI models instead.

## Options

Add these after `mcp` in `args`:

| Flag | Meaning |
|---|---|
| `--allow-ports 3000,5173` | Only let the assistant share these ports. Recommended. |
| `--max-tunnels 5` | Maximum tunnels open at once. |
| `--server tunnel.example.com` | Use your own server instead of the free `publiclocal.app`. |
| `--token ...` | Token for your own server (or set `PUBLICLOCAL_TOKEN`). |
| `--debug` | Log to stderr. |

Example with your own server and an allow list:

```json
{
  "mcpServers": {
    "publiclocal": {
      "command": "publiclocal",
      "args": ["mcp", "--server", "tunnel.example.com", "--allow-ports", "3000,8080"],
      "env": { "PUBLICLOCAL_TOKEN": "your-token" }
    }
  }
}
```

## Safety

A tunnel makes a local app reachable by anyone who has the link. Most assistants ask before each tool call; read what's being shared before you approve. Use `--allow-ports` so an assistant can never expose something you didn't intend, such as a database admin page or another local service. Tunnels never outlive the assistant session.
