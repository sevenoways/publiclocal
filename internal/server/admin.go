package server

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// TunnelStatus describes one connected client for the admin API.
type TunnelStatus struct {
	IP      string    `json:"ip"`
	Account string    `json:"account,omitempty"`
	URLs    []string  `json:"urls"`
	Created time.Time `json:"created"`
	Bytes   int64     `json:"bytes"`
}

// AdminHandler serves the admin API. Bind it to localhost. Requests that a
// browser made (anything carrying Origin or Sec-Fetch-Site) are refused, so a
// web page open on the server cannot drive it; AdminToken adds a bearer token
// on top.
//
//	GET  /tunnels          list connected clients
//	POST /kill?sub=NAME    close the session holding a subdomain
//	POST /kill?ip=ADDR     close every session from an IP
//	POST /ban?ip=ADDR      ban an IP and close its sessions
//	POST /unban?ip=ADDR    lift a ban
//	GET  /bans             list banned IPs
//	GET  /links            every live link, online or not
//	POST /forget?sub=NAME  remove a link without banning anyone
//	GET  /flags            links the misuse checker flagged
//	POST /scan             run the misuse checker now
//	POST /suspend?sub=NAME remove a link and ban its IP and account
//	POST /unban-user?login=NAME
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tunnels", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Tunnels())
	})
	mux.HandleFunc("GET /bans", func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		ips := make([]string, 0, len(s.bans))
		for ip := range s.bans {
			ips = append(ips, ip)
		}
		s.mu.RUnlock()
		slices.Sort(ips)
		writeJSON(w, ips)
	})
	mux.HandleFunc("POST /kill", func(w http.ResponseWriter, r *http.Request) {
		sub, ip := r.URL.Query().Get("sub"), r.URL.Query().Get("ip")
		if sub == "" && ip == "" {
			http.Error(w, "need sub or ip", http.StatusBadRequest)
			return
		}
		writeJSON(w, map[string]int{"closed": s.Kill(sub, ip)})
	})
	mux.HandleFunc("POST /ban", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if net.ParseIP(ip) == nil {
			http.Error(w, "need a valid ip", http.StatusBadRequest)
			return
		}
		if err := s.Ban(ip); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]int{"closed": s.Kill("", ip)})
	})
	mux.HandleFunc("GET /links", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Links())
	})
	mux.HandleFunc("POST /forget", func(w http.ResponseWriter, r *http.Request) {
		if !s.Forget(r.URL.Query().Get("sub")) {
			http.Error(w, "no such link", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /flags", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.Flags())
	})
	mux.HandleFunc("POST /scan", func(w http.ResponseWriter, r *http.Request) {
		flags := s.ScanNow()
		if flags == nil {
			flags = []*Flag{}
		}
		writeJSON(w, flags)
	})
	mux.HandleFunc("POST /suspend", func(w http.ResponseWriter, r *http.Request) {
		ip, login, ok := s.Suspend(r.URL.Query().Get("sub"))
		if !ok {
			http.Error(w, "no such link", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]string{"banned_ip": ip, "banned_account": login})
	})
	mux.HandleFunc("POST /unban-user", func(w http.ResponseWriter, r *http.Request) {
		login := r.URL.Query().Get("login")
		s.mu.Lock()
		a := s.accounts[login]
		if a != nil {
			a.Banned = false
			s.saveLocked()
		}
		s.mu.Unlock()
		if a == nil {
			http.Error(w, "no such account", http.StatusNotFound)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /unban", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Unban(r.URL.Query().Get("ip")); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") != "" || r.Header.Get("Sec-Fetch-Site") != "" {
			http.Error(w, "the admin API does not accept browser requests", http.StatusForbidden)
			return
		}
		if tok := s.cfg.AdminToken; tok != "" {
			got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(tok)) != 1 {
				http.Error(w, "admin token required", http.StatusUnauthorized)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// LinkStatus describes one reserved link, online or not, for the admin API.
type LinkStatus struct {
	Name     string    `json:"name"`
	URL      string    `json:"url"`
	Online   bool      `json:"online"`
	Account  string    `json:"account,omitempty"`
	IP       string    `json:"ip"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires,omitzero"`
	Requests int64     `json:"requests"`
	Visitors int       `json:"visitors"`
	Bytes    int64     `json:"bytes"`
}

// Links lists every live link, oldest first.
func (s *Server) Links() []LinkStatus {
	s.mu.RLock()
	now := time.Now()
	out := make([]LinkStatus, 0, len(s.reservations))
	for sub, res := range s.reservations {
		if res.expired(now) {
			continue
		}
		rt := s.hosts[sub]
		req, bytes, vis := res.live(rt)
		out = append(out, LinkStatus{Name: sub, URL: s.httpURL(sub), Online: rt != nil, Account: res.Account, IP: res.IP, Created: res.Created, Expires: res.Expires, Requests: req, Visitors: vis, Bytes: bytes})
	}
	s.mu.RUnlock()
	slices.SortFunc(out, func(a, b LinkStatus) int { return a.Created.Compare(b.Created) })
	return out
}

// Forget removes a link and closes its session, without banning anyone.
func (s *Server) Forget(sub string) bool {
	sub = strings.ToLower(sub)
	s.mu.Lock()
	res, rt := s.reservations[sub], s.hosts[sub]
	if res == nil && rt == nil {
		s.mu.Unlock()
		return false
	}
	if res != nil {
		if res.timer != nil {
			res.timer.Stop()
		}
		delete(s.reservations, sub)
	}
	delete(s.hosts, sub)
	delete(s.flags, sub)
	s.saveLocked()
	s.mu.Unlock()
	if rt != nil {
		rt.sess.log.Info("link removed by admin", "sub", sub)
		rt.sess.tr.close()
	}
	return true
}

// Tunnels lists connected clients, oldest first.
func (s *Server) Tunnels() []TunnelStatus {
	s.mu.RLock()
	out := make([]TunnelStatus, 0, len(s.sessions))
	for sess := range s.sessions {
		out = append(out, TunnelStatus{IP: sess.ip, Account: sess.account, URLs: sess.urls, Created: sess.created, Bytes: sess.bytes.Load()})
	}
	s.mu.RUnlock()
	slices.SortFunc(out, func(a, b TunnelStatus) int { return a.Created.Compare(b.Created) })
	return out
}

// Kill closes the session holding subdomain sub, or every session from ip.
func (s *Server) Kill(sub, ip string) int {
	s.mu.RLock()
	var victims []*session
	if rt := s.hosts[strings.ToLower(sub)]; sub != "" && rt != nil {
		victims = append(victims, rt.sess)
	}
	if ip != "" {
		key := ipKey(ip)
		for sess := range s.sessions {
			if sess.ipKey == key {
				victims = append(victims, sess)
			}
		}
	}
	s.mu.RUnlock()
	for _, sess := range victims {
		sess.log.Info("session killed by admin")
		sess.tr.close()
	}
	return len(victims)
}

// Ban blocks a client network: an IPv4 address, or the /64 of an IPv6 address.
func (s *Server) Ban(ip string) error {
	ip = ipKey(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bans[ip] {
		return nil
	}
	s.bans[ip] = true
	s.log.Info("ip banned", "ip", ip)
	if s.cfg.BanFile == "" {
		return nil
	}
	f, err := os.OpenFile(s.cfg.BanFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(ip + "\n")
	return err
}

func (s *Server) Unban(ip string) error {
	ip = ipKey(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bans, ip)
	s.log.Info("ip unbanned", "ip", ip)
	if s.cfg.BanFile == "" {
		return nil
	}
	var b strings.Builder
	for ip := range s.bans {
		b.WriteString(ip + "\n")
	}
	return os.WriteFile(s.cfg.BanFile, []byte(b.String()), 0o600)
}

func loadBans(path string) map[string]bool {
	bans := map[string]bool{}
	if path == "" {
		return bans
	}
	f, err := os.Open(path)
	if err != nil {
		return bans
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if ip := strings.TrimSpace(sc.Text()); ip != "" && !strings.HasPrefix(ip, "#") {
			bans[ipKey(ip)] = true
		}
	}
	return bans
}
