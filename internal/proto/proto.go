// Package proto defines the messages exchanged between rtun clients and servers.
//
// A client opens one TCP (optionally TLS) connection to the server and runs a
// yamux session over it. The first stream the client opens is the control
// stream: the client sends a Hello, the server answers with a HelloResp, and
// the stream then stays open for the life of the session. Every other stream
// is opened by the server, one per public connection, and starts with a
// StreamHeader naming the tunnel it belongs to.
//
// Messages are framed as a 4-byte big-endian length followed by JSON.
package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// Version is the protocol version spoken by this build.
const Version = 1

// MaxFrame bounds a single message so a peer cannot make us allocate freely.
const MaxFrame = 64 << 10

const (
	TypeHTTP = "http"
	TypeTCP  = "tcp"
)

type Hello struct {
	Version int         `json:"version"`
	Token   string      `json:"token,omitempty"`
	Tunnels []TunnelReq `json:"tunnels"`
}

type TunnelReq struct {
	Type       string `json:"type"`
	Subdomain  string `json:"subdomain,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
}

type HelloResp struct {
	Error   string       `json:"error,omitempty"`
	Tunnels []TunnelInfo `json:"tunnels,omitempty"`
}

type TunnelInfo struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type StreamHeader struct {
	Tunnel     int    `json:"tunnel"`
	RemoteAddr string `json:"remote_addr,omitempty"`
}

func Write(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxFrame {
		return fmt.Errorf("proto: frame too large (%d bytes)", len(b))
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err = w.Write(buf)
	return err
}

func Read(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrame {
		return fmt.Errorf("proto: frame too large (%d bytes)", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
