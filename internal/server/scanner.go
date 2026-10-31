package server

import (
	"context"
	"io"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Flag is a link the misuse checker thinks may be phishing. Flags are for a
// human to review with `publiclocal admin flags`; nothing is closed automatically.
type Flag struct {
	URL     string    `json:"url"`
	Reason  string    `json:"reason"`
	IP      string    `json:"ip"`
	Account string    `json:"account,omitempty"`
	At      time.Time `json:"at"`
}

func (s *Server) scanLoop() {
	t := time.NewTicker(s.cfg.ScanInterval)
	defer t.Stop()
	for range t.C {
		s.ScanNow()
	}
}

// ScanNow checks a random sample of live links and returns the new flags.
func (s *Server) ScanNow() []*Flag {
	s.mu.RLock()
	subs := make([]string, 0, len(s.hosts))
	for sub := range s.hosts {
		subs = append(subs, sub)
	}
	s.mu.RUnlock()
	rand.Shuffle(len(subs), func(i, j int) { subs[i], subs[j] = subs[j], subs[i] })
	if n := s.cfg.ScanSample; n > 0 && len(subs) > n {
		subs = subs[:n]
	}
	var flags []*Flag
	for _, sub := range subs {
		if f := s.check(sub); f != nil {
			flags = append(flags, f)
		}
	}
	return flags
}

func (s *Server) check(sub string) *Flag {
	s.mu.RLock()
	rt := s.hosts[sub]
	s.mu.RUnlock()
	if rt == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://publiclocal-tunnel/", nil)
	req.Host = sub + "." + s.cfg.Domain
	// Look like an ordinary visitor; the terms page says these checks happen.
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	cl := &http.Client{Transport: rt.proxy.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	reason := phishingReason(string(body))
	if reason == "" {
		return nil
	}
	f := &Flag{URL: s.httpURL(sub), Reason: reason, IP: rt.sess.ip, Account: rt.sess.account, At: time.Now()}
	s.mu.Lock()
	s.flags[sub] = f
	s.mu.Unlock()
	s.log.Warn("possible misuse flagged", "url", f.URL, "reason", reason, "ip", f.IP, "account", f.Account)
	return f
}

var (
	// Asking for these is almost never legitimate on a temporary link.
	walletPhrases = []string{"seed phrase", "recovery phrase", "secret recovery phrase", "mnemonic phrase", "12-word", "24-word", "private key"}
	// Brands commonly impersonated by phishing pages.
	brands = []string{
		"paypal", "apple id", "icloud", "microsoft", "office 365", "outlook", "google", "gmail",
		"facebook", "instagram", "whatsapp", "netflix", "amazon", "coinbase", "binance", "metamask",
		"trust wallet", "dhl", "fedex", "usps", "royal mail", "irs", "hmrc", "wells fargo", "chase",
		"hsbc", "barclays", "santander", "revolut", "bank of america", "online banking",
	}
)

// phishingReason looks for the classic signs of a phishing page: a form that
// asks for a wallet recovery phrase, or a password field next to a brand name.
func phishingReason(html string) string {
	lower := strings.ToLower(html)
	hasForm := strings.Contains(lower, "<input") || strings.Contains(lower, "<textarea")
	hasPassword := strings.Contains(lower, `type="password"`) || strings.Contains(lower, `type='password'`) || strings.Contains(lower, "type=password")
	if hasForm {
		if i := slices.IndexFunc(walletPhrases, func(p string) bool { return strings.Contains(lower, p) }); i >= 0 {
			return "form asks for a wallet " + walletPhrases[i]
		}
	}
	if hasPassword {
		if i := slices.IndexFunc(brands, func(b string) bool { return strings.Contains(lower, b) }); i >= 0 {
			return "password form mentioning " + brands[i]
		}
	}
	return ""
}

// Flags lists links flagged by the misuse checker, newest first.
func (s *Server) Flags() []*Flag {
	s.mu.RLock()
	out := make([]*Flag, 0, len(s.flags))
	for _, f := range s.flags {
		out = append(out, f)
	}
	s.mu.RUnlock()
	slices.SortFunc(out, func(a, b *Flag) int { return b.At.Compare(a.At) })
	return out
}

// Suspend closes a link for good: the link is removed, the network and the
// account behind it are banned, and every other link they hold goes too.
// It returns what it banned.
func (s *Server) Suspend(sub string) (ip, login string, ok bool) {
	sub = strings.ToLower(sub)
	s.mu.Lock()
	res, rt := s.reservations[sub], s.hosts[sub]
	if res == nil && rt == nil {
		s.mu.Unlock()
		return "", "", false
	}
	var key string
	if res != nil {
		ip, key, login = res.IP, res.IPKey, res.Account
	}
	if rt != nil {
		ip, key, login = rt.sess.ip, rt.sess.ipKey, rt.sess.account
	}
	if a := s.accounts[login]; a != nil {
		a.Banned = true
		a.TokenHash = ""
	}
	// Drop every link from the same network or account, not just this one.
	for name, r := range s.reservations {
		if name == sub || r.IPKey == key || (login != "" && r.Account == login) {
			if r.timer != nil {
				r.timer.Stop()
			}
			delete(s.reservations, name)
			delete(s.hosts, name)
			delete(s.flags, name)
		}
	}
	delete(s.hosts, sub)
	delete(s.flags, sub)
	var victims []*session
	for sess := range s.sessions {
		if sess.ipKey == key || (login != "" && sess.account == login) {
			victims = append(victims, sess)
		}
	}
	s.saveLocked()
	s.mu.Unlock()
	if ip != "" {
		s.Ban(ip)
	}
	for _, v := range victims {
		v.tr.close()
	}
	s.log.Warn("link suspended", "sub", sub, "ip", ip, "account", login, "sessions_closed", len(victims))
	return ip, login, true
}
