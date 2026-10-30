<h1 align="center">PublicLocal</h1>

<p align="center">
  <b>Open-source ngrok alternative.</b> Share localhost with a public HTTPS link in one command,<br>
  free on <a href="https://publiclocal.app">publiclocal.app</a> or on your own server. One small Go binary.
</p>

<p align="center">
  <a href="https://github.com/sevenoways/publiclocal/actions/workflows/ci.yml"><img src="https://github.com/sevenoways/publiclocal/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/sevenoways/publiclocal/releases/latest"><img src="https://img.shields.io/github/v/release/sevenoways/publiclocal" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/sevenoways/publiclocal" alt="MIT License"></a>
</p>

```console
$ publiclocal http 3000
Forwarding https://myapp.tunnel.example.com -> 127.0.0.1:3000
```

Share a dev server, test webhooks (Stripe, GitHub, Slack), demo to a client, reach a home lab or a Raspberry Pi behind NAT, or SSH into a machine with no public IP, all on **your own domain**.

## Features

- **HTTPS tunnels on subdomains** with automatic Let's Encrypt certificates
- **TCP tunnels** on public ports: SSH, Postgres, MySQL, Redis, RDP, game servers
- **WebSockets**, HTTP keep-alive and streaming work out of the box
- **Works behind NAT and firewalls**: the client only makes one outbound connection
- **Token authentication** and an encrypted (TLS) control channel
- **Auto-reconnect** with backoff when the network drops
- **Single static binary** for Linux, macOS, Windows and FreeBSD (amd64/arm64), plus a Docker image
- **Live request feed** in your terminal: every request with method, path, status, time and visitor
- **Password-protected links** (`--password`), enforced before anything reaches your app, free server included
- **QR code in the terminal** (`--qr`) to open a link on your phone
- **Link status pages and `/.publiclocal/status`**: visitors see when a link was live and how busy it was; scripts get JSON
- **Works with AI assistants** over MCP: Claude, Cursor, VS Code Copilot, Codex, Gemini CLI. Say "share my dev server" and get a link
- **Public mode** for running an open instance safely: browser warning page, random names, expiring links, rate and traffic limits, ban tools
- **Wildcard certificates** through Cloudflare DNS, so a busy server never hits Let's Encrypt limits
- **MIT licensed**, small and readable Go

## Try it on the free public server

No account, no sign-up. Install, then:

```bash
publiclocal http 3000
# Forwarding https://k7xq2m.publiclocal.app -> 127.0.0.1:3000
```

With no `--server` set, the client uses `publiclocal.app`. Links there are **temporary** and meant for testing and demos: random names, HTTP only, and browsers see a short warning page before your app (webhooks, APIs and `curl` skip it). Links last **24 hours**, and `publiclocal http 3000` comes back with the same address after a reconnect or a restart (add `--new` for a fresh one). Run `publiclocal login` (GitHub) to get **7-day links** that you can extend with `publiclocal extend`. For anything permanent, run your own server (below); it takes two commands.

## Run your own server

You need a server with a public IP (any $5 VPS) and a domain you control. A subdomain of a domain you already own is fine. To run an open instance for others, see [docs/public-instance.md](docs/public-instance.md).

**1. DNS.** Point a name and its wildcard at the server:

```
tunnel.example.com.    A  203.0.113.10
*.tunnel.example.com.  A  203.0.113.10
```

**2. Server.** Open ports 80, 443, 7000 and 10000–20000, then:

```bash
curl -fsSL https://publiclocal.app/install.sh | sh
publiclocal server --domain tunnel.example.com --tokens "$(openssl rand -hex 24)" --acme-email you@example.com
```

Or with Docker:

```bash
docker run -d --name publiclocal --restart unless-stopped --network host \
  -v publiclocal-certs:/certs ghcr.io/sevenoways/publiclocal:latest \
  server --domain tunnel.example.com --tokens YOUR_TOKEN --cert-dir /certs
```

**3. Client.** On your laptop:

```bash
export PUBLICLOCAL_SERVER=tunnel.example.com
export PUBLICLOCAL_TOKEN=YOUR_TOKEN

publiclocal http 3000                      # https://<random>.tunnel.example.com
publiclocal http --subdomain myapp 8080    # https://myapp.tunnel.example.com
publiclocal http --password s3cret 3000    # visitors must enter the password
publiclocal http --qr 3000                 # QR code to scan with a phone
publiclocal tcp 22                         # tcp://tunnel.example.com:1xxxx
publiclocal tcp --remote-port 15432 5432   # fixed public port
```

## Install

| Platform | Command |
|---|---|
| Linux / macOS | `curl -fsSL https://publiclocal.app/install.sh \| sh` |
| Windows (PowerShell) | `irm https://publiclocal.app/install.ps1 \| iex` |
| Docker | `docker pull ghcr.io/sevenoways/publiclocal` |
| Go | `go install github.com/sevenoways/publiclocal/cmd/publiclocal@latest` |

## Use it from AI assistants (MCP)

Ask your assistant to *"share my app on port 3000"* and it opens the tunnel for you:

```bash
claude mcp add publiclocal -- publiclocal mcp       # Claude Code
codex mcp add publiclocal -- publiclocal mcp        # OpenAI Codex CLI
```

Setup for Claude Desktop, Cursor, VS Code, Gemini CLI and more, plus safety options like `--allow-ports`: [docs/mcp.md](docs/mcp.md).

## How it compares

| | PublicLocal | ngrok | frp | cloudflared | bore |
|---|---|---|---|---|---|
| Open source | ✅ MIT | ❌ | ✅ Apache-2.0 | ✅ Apache-2.0 | ✅ MIT |
| Self-hosted server | ✅ | ❌ | ✅ | ❌ (Cloudflare network) | ✅ |
| Your own domain, free | ✅ | paid plans | ✅ | needs domain on Cloudflare | ❌ |
| Automatic HTTPS | ✅ Let's Encrypt | ✅ | manual / plugin | ✅ | ❌ |
| HTTP subdomains | ✅ | ✅ | ✅ | ✅ | ❌ |
| Raw TCP | ✅ | ✅ | ✅ | client needs cloudflared | ✅ |
| Setup | one flag per side | account + token | config files | account + DNS | one command |

Choose **PublicLocal** if you want ngrok-style subdomains with HTTPS on infrastructure you own, set up in two commands. Choose **frp** if you need its larger feature set (UDP, P2P, dashboards, plugins).

## How it works

```
browser ──► publiclocal server ══ one TLS connection (yamux) ══► publiclocal client ──► localhost:3000
```

The client dials the server once and multiplexes that connection with [yamux](https://github.com/hashicorp/yamux). For each public HTTP request or TCP connection, the server opens a stream to the client, which pipes it to your local service. Nothing on your machine accepts inbound connections.

## Server flags

| Flag | Default | |
|---|---|---|
| `--domain` | `$PUBLICLOCAL_DOMAIN` | base domain (required) |
| `--tokens` | `$PUBLICLOCAL_TOKENS` | comma-separated client tokens; empty allows anyone |
| `--control` | `:7000` | port clients connect to |
| `--http` / `--https` | `:80` / `:443` | set `--https ""` to run plain HTTP (e.g. behind your own proxy) |
| `--tcp-ports` | `10000-20000` | range for TCP tunnels |
| `--cert-dir` | `publiclocal-certs` | certificate cache |
| `--acme-email` | | Let's Encrypt contact |
| `--cloudflare-token` | `$CLOUDFLARE_DNS_API_TOKEN` | use one wildcard certificate via Cloudflare DNS |
| `--public` | off | open-instance safeguards; see [docs/public-instance.md](docs/public-instance.md) |
| `--warning` | off | browser warning page (always on with `--public`) |
| `--abuse-contact` | | `mailto:` or `https:` link on the warning page (required with `--public`) |
| `--max-tunnel-age`, `--max-per-ip`, `--rate`, `--max-transfer-mb` | public: 24h, 3, 600/min, 2048 | limits |
| `--admin` | `127.0.0.1:7001` | admin API for `publiclocal admin list/kill/ban` |
| `--ban-file` | | persist banned IPs |
| `--state-file` | | keep links and accounts across restarts |
| `--github-client-id`, `--github-client-secret` | `$GITHUB_CLIENT_ID`, `$GITHUB_CLIENT_SECRET` | enable `publiclocal login` |
| `--max-links-per-ip`, `--max-links-per-account`, `--connects-per-minute` | public: 10, 50, 30 | abuse limits |
| `--admin-token` | `$PUBLICLOCAL_ADMIN_TOKEN` | require a token on the admin API |

If the server runs with `--https ""`, start clients with `--tls=false`.

## Security

- Always set `--tokens` on a public server; without them anyone can publish content on your domain.
- Without HTTPS on the server, tokens and traffic between client and server travel unencrypted.
- Keep tunnels on a dedicated subdomain (or domain) so content others expose can't affect your main site's reputation.
- Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). If PublicLocal is useful to you, a ⭐ helps other people find it.

## License

[MIT](LICENSE)
