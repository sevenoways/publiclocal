# Contributing to PublicLocal

Thanks for helping. Bug reports, docs fixes and features are all welcome.

## Getting started

```bash
git clone https://github.com/sevenoways/publiclocal
cd publiclocal
go test ./...
go build ./cmd/publiclocal
```

The code is small:

- `cmd/publiclocal` — command-line interface
- `internal/server` — public side: control port, HTTP routing, TCP listeners
- `internal/client` — local side: connects, reconnects, forwards streams
- `internal/proto` — wire messages
- `internal/e2e` — end-to-end tests running a real server and client

## Certifying your contribution

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/): by signing off your commits you certify that you wrote the change or have the right to submit it under the project's MIT licence, and that it may be redistributed under that licence (including under a different open-source licence should the project ever need to change it). Sign off with `git commit -s`, which adds a `Signed-off-by: Your Name <you@example.com>` line.

## Pull requests

- Open an issue first for larger changes so we can agree on the approach.
- Add or update a test in `internal/e2e` for behaviour changes.
- Run `gofmt`, `go vet ./...` and `go test ./...` before pushing.
- Keep the project dependency-light; new dependencies need a good reason.

Good first contributions: docs and deployment guides (systemd, Caddy/nginx in front, Kubernetes), a config file for multiple tunnels, request logging in the client, Basic Auth on HTTP tunnels.
