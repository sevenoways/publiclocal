package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"time"
)

// A reservation is a link (subdomain) handed to a client. It outlives the
// connection, so a client that reconnects with the link's claim gets the same
// address back until the reservation expires.
type reservation struct {
	Sub       string    `json:"sub"`
	ClaimHash string    `json:"claim_hash"`
	Account   string    `json:"account,omitempty"` // GitHub login of the owner, if logged in
	IP        string    `json:"ip"`                // client address as seen
	IPKey     string    `json:"ip_key"`            // what limits and bans are keyed on
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires,omitzero"` // zero: never

	timer *time.Timer
}

func (r *reservation) expired(now time.Time) bool {
	return !r.Expires.IsZero() && !now.Before(r.Expires)
}

// account is a user who signed in with GitHub.
type account struct {
	Login        string    `json:"login"`
	GitHubID     int64     `json:"github_id"`
	TokenHash    string    `json:"token_hash,omitempty"`
	TokenCreated time.Time `json:"token_created,omitzero"`
	Created      time.Time `json:"created"`
	Banned       bool      `json:"banned,omitempty"`
}

// persisted is what the state file holds.
type persisted struct {
	CookieKey    string                  `json:"cookie_key"`
	Reservations map[string]*reservation `json:"reservations"`
	Accounts     map[string]*account     `json:"accounts"`
}

func (s *Server) loadState() {
	s.reservations = map[string]*reservation{}
	s.accounts = map[string]*account{}
	s.dirty = make(chan struct{}, 1)
	var p persisted
	if s.cfg.StateFile != "" {
		if b, err := os.ReadFile(s.cfg.StateFile); err == nil {
			if err := json.Unmarshal(b, &p); err != nil {
				s.log.Error("cannot read state file; starting empty", "err", err)
				p = persisted{}
			}
		}
	}
	if key, err := hex.DecodeString(p.CookieKey); err == nil && len(key) == 32 {
		s.cookieKey = key
	} else {
		s.cookieKey = make([]byte, 32)
		rand.Read(s.cookieKey)
	}
	now := time.Now()
	for sub, r := range p.Reservations {
		if !r.expired(now) {
			if r.IPKey == "" {
				r.IPKey = ipKey(r.IP)
			}
			s.reservations[sub] = r
			s.scheduleExpiry(r)
		}
	}
	if p.Accounts != nil {
		s.accounts = p.Accounts
	}
	if s.cfg.StateFile != "" {
		go s.saveLoop()
		s.saveLocked() // persist the cookie key
	}
}

// saveLocked marks the state changed. Callers hold s.mu. Writes are
// coalesced by saveLoop, so a burst of changes costs one file write.
func (s *Server) saveLocked() {
	if s.cfg.StateFile == "" {
		return
	}
	select {
	case s.dirty <- struct{}{}:
	default:
	}
}

func (s *Server) saveLoop() {
	for range s.dirty {
		time.Sleep(time.Second)
		s.writeState()
	}
}

// Flush writes the state now, e.g. at shutdown, instead of waiting for saveLoop.
func (s *Server) Flush() {
	if s.cfg.StateFile != "" {
		s.writeState()
	}
}

func (s *Server) writeState() {
	s.mu.RLock()
	b, err := json.MarshalIndent(persisted{CookieKey: hex.EncodeToString(s.cookieKey), Reservations: s.reservations, Accounts: s.accounts}, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		s.log.Error("cannot encode state", "err", err)
		return
	}
	tmp := s.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		s.log.Error("cannot write state", "err", err)
		return
	}
	if err := os.Rename(tmp, s.cfg.StateFile); err != nil {
		s.log.Error("cannot write state", "err", err)
	}
}

// scheduleExpiry closes the link when its reservation runs out. Callers hold
// s.mu or own r exclusively.
func (s *Server) scheduleExpiry(r *reservation) {
	if r.Expires.IsZero() {
		return
	}
	if r.timer != nil {
		r.timer.Stop()
	}
	r.timer = time.AfterFunc(time.Until(r.Expires), func() { s.expire(r) })
}

func (s *Server) expire(r *reservation) {
	s.mu.Lock()
	if s.reservations[r.Sub] != r {
		s.mu.Unlock()
		return
	}
	if !r.expired(time.Now()) { // extended since the timer was set
		s.scheduleExpiry(r)
		s.mu.Unlock()
		return
	}
	delete(s.reservations, r.Sub)
	delete(s.flags, r.Sub)
	rt := s.hosts[r.Sub]
	delete(s.hosts, r.Sub)
	s.saveLocked()
	s.mu.Unlock()
	if rt != nil {
		rt.sess.log.Info("link expired", "sub", r.Sub)
		rt.sess.ys.Close()
	}
}

// Random link names use letters without vowels, plus digits that can't be
// mistaken for letters, so a name never spells a word or a brand.
const nameAlphabet = "bcdfghjkmnpqrstvwxz23456789"

func randomName(minLen, maxLen int) string {
	n := minLen
	if maxLen > minLen {
		d, _ := rand.Int(rand.Reader, big.NewInt(int64(maxLen-minLen+1)))
		n += int(d.Int64())
	}
	b := make([]byte, n)
	for i := range b {
		c, _ := rand.Int(rand.Reader, big.NewInt(int64(len(nameAlphabet))))
		b[i] = nameAlphabet[c.Int64()]
	}
	return string(b)
}

func newSecret() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashSecret(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func secretMatches(secret, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(hash)) == 1
}
