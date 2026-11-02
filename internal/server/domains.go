package server

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Custom domains: a signed-in user proves they control a name with a TXT
// record, points it at this server with a CNAME, and attaches a link to it
// with --domain. The server gets a certificate for the name on first use.

// customDomain is one name a user has added, persisted in the state file.
type customDomain struct {
	Host     string    `json:"host"`
	Account  string    `json:"account"`
	Created  time.Time `json:"created"`
	Verified time.Time `json:"verified,omitzero"` // zero until the TXT record checks out
	Sub      string    `json:"sub,omitempty"`     // link last attached to the name
}

const (
	domainTXTPrefix     = "_publiclocal."
	domainVerifyPrefix  = "publiclocal-verify="
	maxDomainsDefault   = 5
	domainVerifyTimeout = 10 * time.Second
	domainRecheck       = 24 * time.Hour // verified names are checked again this often
	unverifiedTTL       = 7 * 24 * time.Hour
	certFailTTL         = time.Hour // after a failed issuance, no retry for this long
	verifiesPerMinute   = 5
)

var hostnameRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// domainToken is what the TXT record must carry. It is per account, so a
// name verified for one user never counts for another.
func (s *Server) domainToken(login string) string {
	m := hmac.New(sha256.New, s.cookieKey)
	m.Write([]byte("domain:" + login))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// checkDomainName validates a name a user wants to add.
func (s *Server) checkDomainName(host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch {
	case len(host) > 253 || !hostnameRE.MatchString(host):
		return "", errors.New("not a valid host name")
	case host == s.cfg.Domain || strings.HasSuffix(host, "."+s.cfg.Domain):
		return "", fmt.Errorf("names under %s are links, not custom domains", s.cfg.Domain)
	case strings.Count(host, ".") < 2:
		return "", errors.New("use a subdomain such as demo.example.com; a bare domain cannot have a CNAME")
	}
	return host, nil
}

// lookupTXT is net.DefaultResolver unless a test replaces it.
func (s *Server) lookupTXT(ctx context.Context, name string) ([]string, error) {
	if s.cfg.LookupTXT != nil {
		return s.cfg.LookupTXT(ctx, name)
	}
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// verifyDomain checks the TXT record and marks the name verified. Callers
// must not hold s.mu.
func (s *Server) verifyDomain(ctx context.Context, host, login string) error {
	ctx, cancel := context.WithTimeout(ctx, domainVerifyTimeout)
	defer cancel()
	want := domainVerifyPrefix + s.domainToken(login)
	records, err := s.lookupTXT(ctx, domainTXTPrefix+host)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return fmt.Errorf("no TXT record at %s%s yet (DNS changes can take a few minutes)", domainTXTPrefix, host)
		}
		return fmt.Errorf("DNS lookup failed: %v", err)
	}
	ok := false
	for _, r := range records {
		if strings.TrimSpace(r) == want {
			ok = true
		}
	}
	if !ok {
		return fmt.Errorf("the TXT record at %s%s does not contain %s", domainTXTPrefix, host, want)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.domains[host]
	if d == nil || d.Account != login {
		return errors.New("this name is not on your account")
	}
	d.Verified = time.Now()
	s.saveLocked()
	return nil
}

// domainVerified reports whether a name may serve traffic. Callers hold s.mu.
func (s *Server) domainVerified(host string) *customDomain {
	d := s.domains[host]
	if d == nil || d.Verified.IsZero() {
		return nil
	}
	if a := s.accounts[d.Account]; a == nil || a.Banned {
		return nil
	}
	return d
}

// attachDomain binds a link to a custom name. Callers hold s.mu.
func (s *Server) attachDomain(host, sub, login string) error {
	host = strings.ToLower(host)
	d := s.domains[host]
	switch {
	case login == "":
		return errors.New("custom domains need a signed-in account; run publiclocal login")
	case d == nil || d.Account != login:
		return fmt.Errorf("%s is not on your account; run publiclocal domains add %s", host, host)
	case d.Verified.IsZero():
		return fmt.Errorf("%s is not verified yet; run publiclocal domains verify %s", host, host)
	}
	for _, rt := range s.hosts {
		if rt.domain == host && s.hosts[sub] != rt {
			return fmt.Errorf("%s is attached to another live link", host)
		}
	}
	d.Sub = sub
	s.saveLocked()
	return nil
}

// Account API on the bare domain.

func (s *Server) domainsAPI(w http.ResponseWriter, r *http.Request) {
	login, ok := s.bearer(w, r)
	if !ok {
		return
	}
	if r.URL.Path == "/api/domains" && r.Method == http.MethodGet {
		s.mu.RLock()
		var out []map[string]any
		for _, d := range s.domains {
			if d.Account == login {
				out = append(out, map[string]any{"host": d.Host, "verified": !d.Verified.IsZero(), "link": d.Sub, "txt_name": domainTXTPrefix + d.Host, "txt_value": domainVerifyPrefix + s.domainToken(login), "cname": s.cfg.Domain})
			}
		}
		s.mu.RUnlock()
		sort.Slice(out, func(i, j int) bool { return out[i]["host"].(string) < out[j]["host"].(string) })
		if out == nil {
			out = []map[string]any{}
		}
		writeJSON(w, map[string]any{"domains": out})
		return
	}
	var in struct{ Host string }
	if r.Method != http.MethodPost || json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil {
		apiError(w, http.StatusBadRequest, "POST {host}")
		return
	}
	host, err := s.checkDomainName(in.Host)
	if err != nil {
		apiError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch r.URL.Path {
	case "/api/domains":
		s.mu.Lock()
		s.purgeDomainsLocked()
		if d := s.domains[host]; d != nil && d.Account != login {
			if !d.Verified.IsZero() {
				s.mu.Unlock()
				apiError(w, http.StatusConflict, "this name is verified by another account")
				return
			}
			delete(s.domains, host) // never verified: whoever proves control with the TXT record wins
		}
		mine := 0
		for _, d := range s.domains {
			if d.Account == login {
				mine++
			}
		}
		limit := s.cfg.MaxDomainsPerAccount
		if limit <= 0 {
			limit = maxDomainsDefault
		}
		if s.domains[host] == nil && mine >= limit {
			s.mu.Unlock()
			apiError(w, http.StatusForbidden, fmt.Sprintf("at most %d custom domains per account", limit))
			return
		}
		if s.domains[host] == nil {
			s.domains[host] = &customDomain{Host: host, Account: login, Created: time.Now()}
			s.saveLocked()
		}
		s.mu.Unlock()
		writeJSON(w, map[string]any{"host": host, "txt_name": domainTXTPrefix + host, "txt_value": domainVerifyPrefix + s.domainToken(login), "cname": s.cfg.Domain})
	case "/api/domains/verify":
		if !s.verifyLimit.allow(login) {
			apiError(w, http.StatusTooManyRequests, "too many checks; DNS changes take a few minutes, try again shortly")
			return
		}
		if err := s.verifyDomain(r.Context(), host, login); err != nil {
			apiError(w, http.StatusConflict, err.Error())
			return
		}
		s.log.Info("custom domain verified", "host", host, "login", login)
		writeJSON(w, map[string]any{"host": host, "verified": true})
	case "/api/domains/remove":
		s.mu.Lock()
		if d := s.domains[host]; d != nil && d.Account == login {
			delete(s.domains, host)
			for _, rt := range s.hosts {
				if rt.domain == host {
					rt.domain = ""
				}
			}
			s.saveLocked()
		}
		s.mu.Unlock()
		writeJSON(w, map[string]any{"host": host, "removed": true})
	default:
		apiError(w, http.StatusNotFound, "unknown domains call")
	}
}

// purgeDomainsLocked drops names that were added but never verified.
func (s *Server) purgeDomainsLocked() {
	now := time.Now()
	for h, d := range s.domains {
		if d.Verified.IsZero() && now.Sub(d.Created) > unverifiedTTL {
			delete(s.domains, h)
		}
	}
}

// recheckDomains re-verifies names every so often, so a name that changed
// hands or lost its TXT record stops working. A DNS outage is not a reason
// to drop a name; only a clear "no" is.
func (s *Server) recheckDomains(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var due []*customDomain
		s.mu.Lock()
		s.purgeDomainsLocked()
		for _, d := range s.domains {
			if !d.Verified.IsZero() && time.Since(d.Verified) > domainRecheck {
				c := *d
				due = append(due, &c)
			}
		}
		s.mu.Unlock()
		for _, d := range due {
			err := s.verifyDomain(ctx, d.Host, d.Account)
			if err == nil || ctx.Err() != nil {
				continue
			}
			if !strings.Contains(err.Error(), "DNS lookup failed") {
				s.mu.Lock()
				if cur := s.domains[d.Host]; cur != nil && cur.Account == d.Account {
					cur.Verified = time.Time{}
					for _, rt := range s.hosts {
						if rt.domain == d.Host {
							rt.domain = ""
						}
					}
					s.saveLocked()
				}
				s.mu.Unlock()
				s.log.Info("custom domain no longer verified", "host", d.Host, "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

// Certificates. Links use the wildcard (or autocert); custom names always
// go through autocert, which only ever asks for verified names.

func (s *Server) customHostPolicy(_ context.Context, host string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.domainVerified(strings.ToLower(host)) != nil {
		return nil
	}
	return errors.New("publiclocal: not a verified custom domain")
}

func (s *Server) newCustomCerts() *autocert.Manager {
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(s.cfg.CertDir),
		Email:      s.cfg.ACMEEmail,
		HostPolicy: s.customHostPolicy,
	}
}

// certSplitter serves the base domain and links from one source and custom
// names from autocert.
func (s *Server) certSplitter(base func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	s.customCerts = s.newCustomCerts()
	return &tls.Config{
		NextProtos: []string{"h2", "http/1.1", acme.ALPNProto},
		GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := strings.ToLower(h.ServerName)
			if host == "" || host == s.cfg.Domain || strings.HasSuffix(host, "."+s.cfg.Domain) {
				return base(h)
			}
			// A name whose issuance just failed (CNAME not pointing here yet,
			// say) is not retried on every handshake: that would burn Let's
			// Encrypt's failed-validation quota for the whole server.
			s.certFailMu.Lock()
			until, failed := s.certFail[host]
			s.certFailMu.Unlock()
			if failed && time.Now().Before(until) {
				return nil, errors.New("publiclocal: certificate for this name failed recently; retry later")
			}
			c, err := s.customCerts.GetCertificate(h)
			if err != nil && s.customHostPolicy(context.Background(), host) == nil {
				s.certFailMu.Lock()
				if s.certFail == nil {
					s.certFail = map[string]time.Time{}
				}
				s.certFail[host] = time.Now().Add(certFailTTL)
				s.certFailMu.Unlock()
			}
			return c, err
		},
	}
}
