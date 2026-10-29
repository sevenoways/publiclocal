# rtun

A small, self-hosted reverse tunnel. Run the server on any public box with a domain, then expose a local port from anywhere:

```bash
rtun http 3000
# Forwarding https://a1b2c3d4.tunnel.example.com -> 127.0.0.1:3000
```

- **HTTP tunnels** on subdomains, with automatic HTTPS from Let's Encrypt
- **TCP tunnels** on public ports (SSH, databases, game servers, ...)
- WebSockets and keep-alive work through HTTP tunnels
- Token auth, TLS-encrypted control connection, auto-reconnect
- One static binary for server and client, no runtime dependencies

## How it works

The client opens a single outbound connection to the server and multiplexes it with [yamux](https://github.com/hashicorp/yamux). When a request arrives at `name.tunnel.example.com` or a TCP port, the server opens a stream down that connection and the client pipes it to your local service. Nothing on your machine needs to accept inbound connections.

```
browser ──► rtun server ══ one TLS connection ══► rtun client ──► localhost:3000
```

## Install

Download a binary from [Releases](https://github.com/sevenoways/reverse-tunnel/releases), or:

```bash
go install github.com/sevenoways/reverse-tunnel/cmd/rtun@latest
```

## Server setup

1. Point DNS at your server — both the domain and a wildcard:
   ```
   tunnel.example.com.    A  203.0.113.10
   *.tunnel.example.com.  A  203.0.113.10
   ```
2. Open ports 80, 443, 7000 and your TCP range (default 10000–20000).
3. Run:
   ```bash
   rtun server --domain tunnel.example.com --tokens "$(openssl rand -hex 24)" --acme-email you@example.com
   ```

Certificates are issued per subdomain on first request and cached in `--cert-dir`.

| Flag | Default | |
|---|---|---|
| `--domain` | `$RTUN_DOMAIN` | base domain (required) |
| `--tokens` | `$RTUN_TOKENS` | comma-separated client tokens; empty allows anyone |
| `--control` | `:7000` | client connection port |
| `--http` / `--https` | `:80` / `:443` | set `--https ""` to run without TLS (e.g. behind a proxy) |
| `--tcp-ports` | `10000-20000` | range for TCP tunnels |
| `--cert-dir` | `rtun-certs` | certificate cache |

## Client

```bash
export RTUN_SERVER=tunnel.example.com
export RTUN_TOKEN=...

rtun http 3000                       # random subdomain
rtun http --subdomain myapp 8080     # https://myapp.tunnel.example.com
rtun tcp 22                          # tcp://tunnel.example.com:1xxxx
rtun tcp --remote-port 15432 5432
```

If the server runs with `--https ""`, pass `--tls=false` to the client.

## Security notes

- Always set `--tokens` on a public server; without them anyone can publish content on your domain.
- Without HTTPS on the server, tokens and traffic between client and server are sent in the clear.
- The public host header is passed through to your local app unchanged.

## Development

```bash
go test ./...
go build ./cmd/rtun
```

## License

MIT
