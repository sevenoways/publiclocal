package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/registration"
)

// wildcard holds one Let's Encrypt certificate for the domain and *.domain,
// obtained with a DNS-01 challenge through the Cloudflare API. One certificate
// covers every tunnel, which keeps a busy public server far below Let's
// Encrypt's per-domain issuance limits.
type wildcard struct {
	domain, dir, email, token string
	log                       *slog.Logger

	mu   sync.RWMutex
	cert *tls.Certificate
}

const renewBefore = 30 * 24 * time.Hour

func newWildcard(domain, dir, email, token string, log *slog.Logger) (*wildcard, error) {
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	w := &wildcard{domain: domain, dir: dir, email: email, token: token, log: log}
	if err := w.load(); err == nil && !w.needsRenewal() {
		log.Info("using cached wildcard certificate", "expires", w.cert.Leaf.NotAfter)
		return w, nil
	}
	if err := w.obtain(); err != nil {
		if w.cert != nil {
			log.Warn("wildcard renewal failed, using cached certificate", "err", err)
			return w, nil
		}
		return nil, err
	}
	return w, nil
}

func (w *wildcard) certPath() string { return filepath.Join(w.dir, "wildcard."+w.domain+".crt") }
func (w *wildcard) keyPath() string  { return filepath.Join(w.dir, "wildcard."+w.domain+".key") }

func (w *wildcard) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cert, nil
}

func (w *wildcard) load() error {
	c, err := tls.LoadX509KeyPair(w.certPath(), w.keyPath())
	if err != nil {
		return err
	}
	return w.set(&c)
}

func (w *wildcard) set(c *tls.Certificate) error {
	if c.Leaf == nil {
		leaf, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			return err
		}
		c.Leaf = leaf
	}
	w.mu.Lock()
	w.cert = c
	w.mu.Unlock()
	return nil
}

func (w *wildcard) needsRenewal() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.cert == nil || time.Until(w.cert.Leaf.NotAfter) < renewBefore
}

func (w *wildcard) renewLoop(ctx context.Context) {
	t := time.NewTicker(12 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if w.needsRenewal() {
				if err := w.obtain(); err != nil {
					w.log.Error("wildcard renewal failed", "err", err)
				}
			}
		}
	}
}

func (w *wildcard) obtain() error {
	w.log.Info("requesting wildcard certificate", "domain", w.domain)
	key, err := w.accountKey()
	if err != nil {
		return err
	}
	u := &acmeUser{email: w.email, key: key}
	cfg := lego.NewConfig(u)
	cfg.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(cfg)
	if err != nil {
		return err
	}
	cf := cloudflare.NewDefaultConfig()
	cf.AuthToken = w.token
	provider, err := cloudflare.NewDNSProviderConfig(cf)
	if err != nil {
		return err
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return err
	}
	// Registering with an existing key returns the existing account.
	if u.reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true}); err != nil {
		return err
	}
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: []string{w.domain, "*." + w.domain}, Bundle: true})
	if err != nil {
		return err
	}
	c, err := tls.X509KeyPair(res.Certificate, res.PrivateKey)
	if err != nil {
		return err
	}
	if err := os.WriteFile(w.certPath(), res.Certificate, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(w.keyPath(), res.PrivateKey, 0o600); err != nil {
		return err
	}
	if err := w.set(&c); err != nil {
		return err
	}
	w.log.Info("wildcard certificate ready", "expires", c.Leaf.NotAfter)
	return nil
}

func (w *wildcard) accountKey() (crypto.PrivateKey, error) {
	path := filepath.Join(w.dir, "acme-account.key")
	if b, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(b)
		if block == nil {
			return nil, errors.New("acme-account.key: no PEM data")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return key, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

type acmeUser struct {
	email string
	key   crypto.PrivateKey
	reg   *registration.Resource
}

func (u *acmeUser) GetEmail() string                        { return u.email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }
