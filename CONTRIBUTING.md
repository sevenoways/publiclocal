# Contributing to rtun

Thanks for helping. Bug reports, docs fixes and features are all welcome.

## Getting started

```bash
git clone https://github.com/sevenoways/rtun
cd rtun
go test ./...
go build ./cmd/rtun
```

The code is small:

- `cmd/rtun` — command-line interface
- `internal/server` — public side: control port, HTTP routing, TCP listeners
- `internal/client` — local side: connects, reconnects, forwards streams
- `internal/proto` — wire messages
- `internal/e2e` — end-to-end tests running a real server and client

## Pull requests

- Open an issue first for larger changes so we can agree on the approach.
- Add or update a test in `internal/e2e` for behaviour changes.
- Run `gofmt`, `go vet ./...` and `go test ./...` before pushing.
- Keep the project dependency-light; new dependencies need a good reason.

Good first contributions: docs and deployment guides (systemd, Caddy/nginx in front, Kubernetes), a config file for multiple tunnels, request logging in the client, Basic Auth on HTTP tunnels.
