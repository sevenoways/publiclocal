FROM golang:1.27-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /rtun ./cmd/rtun

# Runs as root so the server can bind ports 80 and 443 with --network host.
FROM gcr.io/distroless/static-debian12
COPY --from=build /rtun /rtun
ENTRYPOINT ["/rtun"]
