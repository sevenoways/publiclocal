package server

import (
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ipKey turns a client address into the key that limits and bans use. IPv4
// addresses are used as they are; IPv6 clients usually own a whole /64, so
// the key is that /64, which stops a single machine from rotating through
// addresses to dodge limits.
func ipKey(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		addr = h
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return strings.ToLower(addr)
	}
	ip = ip.Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.Masked().String()
	}
	return ip.String()
}

// rateLimiter holds a token bucket per key, dropping idle ones.
type rateLimiter struct {
	perMinute int
	mu        sync.Mutex
	buckets   map[string]*bucket
	calls     int
}

func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{perMinute: perMinute, buckets: map[string]*bucket{}}
}

func (l *rateLimiter) allow(key string) bool {
	if l == nil || l.perMinute <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.calls%1000 == 0 {
		cutoff := time.Now().Add(-10 * time.Minute)
		for k, b := range l.buckets {
			b.mu.Lock()
			idle := b.last.Before(cutoff)
			b.mu.Unlock()
			if idle {
				delete(l.buckets, k)
			}
		}
	}
	b := l.buckets[key]
	if b == nil {
		b = newBucket(l.perMinute)
		l.buckets[key] = b
	}
	return b.allow()
}
