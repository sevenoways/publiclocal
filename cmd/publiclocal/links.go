package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Links the client was given are remembered per server and local address,
// so `publiclocal http 3000` comes back with the same link after a restart
// until it expires.
type storedLink struct {
	Name    string    `json:"name"`
	Claim   string    `json:"claim"`
	Expires time.Time `json:"expires,omitzero"`
}

func linksPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "publiclocal", "links.json"), nil
}

func linkKey(server, local string) string { return serverHost(server) + "|" + local }

func loadLinks() map[string]storedLink {
	links := map[string]storedLink{}
	if p, err := linksPath(); err == nil {
		if b, err := os.ReadFile(p); err == nil {
			json.Unmarshal(b, &links)
		}
	}
	return links
}

func saveLinks(links map[string]storedLink) {
	p, err := linksPath()
	if err != nil {
		return
	}
	now := time.Now()
	for k, l := range links {
		if !l.Expires.IsZero() && !now.Before(l.Expires) {
			delete(links, k)
		}
	}
	os.MkdirAll(filepath.Dir(p), 0o700)
	b, _ := json.MarshalIndent(links, "", "  ")
	os.WriteFile(p, b, 0o600)
}

func loadLink(key string) *storedLink {
	l, ok := loadLinks()[key]
	if !ok || (!l.Expires.IsZero() && !time.Now().Before(l.Expires)) {
		return nil
	}
	return &l
}

func saveLink(key string, l storedLink) {
	links := loadLinks()
	links[key] = l
	saveLinks(links)
}

func deleteLink(key string) {
	links := loadLinks()
	delete(links, key)
	saveLinks(links)
}
