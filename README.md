<h1 align="center">rtun</h1>

<p align="center">
  <b>Self-hosted ngrok alternative.</b> Expose localhost to the internet over HTTPS and TCP through your own server.<br>
  One small Go binary. No account, no limits, no vendor.
</p>

<p align="center">
  <a href="https://github.com/sevenoways/rtun/actions/workflows/ci.yml"><img src="https://github.com/sevenoways/rtun/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/sevenoways/rtun/releases/latest"><img src="https://img.shields.io/github/v/release/sevenoways/rtun" alt="Release"></a>
  <a href="https://pkg.go.dev/github.com/sevenoways/rtun"><img src="https://pkg.go.dev/badge/github.com/sevenoways/rtun.svg" alt="Go Reference"></a>
  <a href="https://goreportcard.com/report/github.com/sevenoways/rtun"><img src="https://goreportcard.com/badge/github.com/sevenoways/rtun" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/sevenoways/rtun" alt="MIT License"></a>
</p>

```console
$ rtun http 3000
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
- **MIT licensed**, about 800 lines of readable Go

## Quick start

You need a server with a public IP (any $5 VPS) and a domain you control. A subdomain of a domain you already own is fine.

**1. DNS.** Point a name and its wildcard at the server:

```
tunnel.example.com.    A  203.0.113.10
*.tunnel.example.com.  A  203.0.113.10
```

**2. Server.** Open ports 80, 443, 7000 and 10000–20000, then:

```bash
curl -fsSL https://raw.githubusercontent.com/sevenoways/rtun/main/install.sh | sh
rtun server --domain tunnel.example.com --tokens "$(openssl rand -hex 24)" --acme-email you@example.com
```

Or with Docker:

```bash
docker run -d --name rtun --restart unless-stopped --network host \
  -v rtun-certs:/certs ghcr.io/sevenoways/rtun:latest \
  server --domain tunnel.example.com --tokens YOUR_TOKEN --cert-dir /certs
```

**3. Client.** On your laptop:

```bash
export RTUN_SERVER=tunnel.example.com
export RTUN_TOKEN=YOUR_TOKEN

rtun http 3000                      # https://<random>.tunnel.example.com
rtun http --subdomain myapp 8080    # https://myapp.tunnel.example.com
rtun tcp 22                         # tcp://tunnel.example.com:1xxxx
rtun tcp --remote-port 15432 5432   # fixed public port
```

## Install

| Platform | Command |
|---|---|
| Linux / macOS | `curl -fsSL https://raw.githubusercontent.com/sevenoways/rtun/main/install.sh \| sh` |
| Windows | download the zip from [Releases](https://github.com/sevenoways/rtun/releases/latest) |
| Docker | `docker pull ghcr.io/sevenoways/rtun` |
| Go | `go install github.com/sevenoways/rtun/cmd/rtun@latest` |

## How it compares

| | rtun | ngrok | frp | cloudflared | bore |
|---|---|---|---|---|---|
| Open source | ✅ MIT | ❌ | ✅ Apache-2.0 | ✅ Apache-2.0 | ✅ MIT |
| Self-hosted server | ✅ | ❌ | ✅ | ❌ (Cloudflare network) | ✅ |
| Your own domain, free | ✅ | paid plans | ✅ | needs domain on Cloudflare | ❌ |
| Automatic HTTPS | ✅ Let's Encrypt | ✅ | manual / plugin | ✅ | ❌ |
| HTTP subdomains | ✅ | ✅ | ✅ | ✅ | ❌ |
| Raw TCP | ✅ | ✅ | ✅ | client needs cloudflared | ✅ |
| Setup | one flag per side | account + token | config files | account + DNS | one command |

Choose **rtun** if you want ngrok-style subdomains with HTTPS on infrastructure you own, set up in two commands. Choose **frp** if you need its larger feature set (UDP, P2P, dashboards, plugins).

## How it works

```
browser ──► rtun server ══ one TLS connection (yamux) ══► rtun client ──► localhost:3000
```

The client dials the server once and multiplexes that connection with [yamux](https://github.com/hashicorp/yamux). For each public HTTP request or TCP connection, the server opens a stream to the client, which pipes it to your local service. Nothing on your machine accepts inbound connections.

## Server flags

| Flag | Default | |
|---|---|---|
| `--domain` | `$RTUN_DOMAIN` | base domain (required) |
| `--tokens` | `$RTUN_TOKENS` | comma-separated client tokens; empty allows anyone |
| `--control` | `:7000` | port clients connect to |
| `--http` / `--https` | `:80` / `:443` | set `--https ""` to run plain HTTP (e.g. behind your own proxy) |
| `--tcp-ports` | `10000-20000` | range for TCP tunnels |
| `--cert-dir` | `rtun-certs` | certificate cache |
| `--acme-email` | | Let's Encrypt contact |

If the server runs with `--https ""`, start clients with `--tls=false`.

## Security

- Always set `--tokens` on a public server; without them anyone can publish content on your domain.
- Without HTTPS on the server, tokens and traffic between client and server travel unencrypted.
- Keep tunnels on a dedicated subdomain (or domain) so content others expose can't affect your main site's reputation.
- Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). If rtun is useful to you, a ⭐ helps other people find it.

## License

[MIT](LICENSE)
