FROM golang:1.27.3-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /publiclocal ./cmd/publiclocal

# Runs as root so the server can bind ports 80 and 443 with --network host.
FROM gcr.io/distroless/static-debian12
COPY --from=build /publiclocal /publiclocal
ENTRYPOINT ["/publiclocal"]
