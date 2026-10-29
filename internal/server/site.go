package server

import (
	"io/fs"
	"net/http"
	"strings"
)

// reserved subdomains are never handed to tunnels, so they stay available
// for the project's own pages and mail.
var reserved = map[string]bool{
	"www": true, "api": true, "admin": true, "mail": true, "status": true,
	"docs": true, "abuse": true, "app": true, "dashboard": true, "login": true,
}

func (s *Server) serveSite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	if s.scheme == "https" {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
	if strings.HasSuffix(r.URL.Path, ".sh") {
		h.Set("Content-Type", "text/plain; charset=utf-8")
	}
	http.FileServer(siteFS{http.Dir(s.cfg.SiteDir)}).ServeHTTP(w, r)
}

// siteFS hides dotfiles and directory listings, and lets /terms serve terms.html.
type siteFS struct{ fs http.FileSystem }

func (f siteFS) Open(name string) (http.File, error) {
	for part := range strings.SplitSeq(name, "/") {
		if strings.HasPrefix(part, ".") {
			return nil, errNotExist
		}
	}
	file, err := f.fs.Open(name)
	if err != nil && !strings.Contains(name[strings.LastIndex(name, "/")+1:], ".") {
		return f.fs.Open(name + ".html")
	}
	if err != nil {
		return nil, err
	}
	if st, err := file.Stat(); err == nil && st.IsDir() {
		idx, err := f.fs.Open(strings.TrimSuffix(name, "/") + "/index.html")
		if err != nil {
			file.Close()
			return nil, errNotExist
		}
		idx.Close()
	}
	return file, nil
}

var errNotExist = fs.ErrNotExist
