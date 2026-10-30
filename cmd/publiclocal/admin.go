package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// runAdmin talks to a running server's admin API, normally on the same machine.
func runAdmin(args []string) error {
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:7001", "server admin API address")
	token := fs.String("token", os.Getenv("PUBLICLOCAL_ADMIN_TOKEN"), "admin token, if the server requires one (env PUBLICLOCAL_ADMIN_TOKEN)")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: publiclocal admin [--addr host:port] <command>

  list              connected clients and their tunnels
  links             every live link, online or offline, with owner, traffic and expiry
  forget <link>     remove a link (and close its tunnel) without banning anyone
  kill <sub|ip>     close the session holding a subdomain, or all sessions from an IP
  ban <ip>          ban an IP and close its sessions
  unban <ip>        lift a ban
  bans              list banned IPs
  flags             links the misuse checker flagged as possible phishing
  scan              check a random sample of live links now
  suspend <link>    remove a link and ban the IP and GitHub account behind it
  unban-user <login> lift a ban on a GitHub account
`)
	}
	fs.Parse(args)

	method, path, q := http.MethodGet, "", url.Values{}
	switch cmd, arg := fs.Arg(0), fs.Arg(1); {
	case cmd == "list" && fs.NArg() == 1:
		path = "/tunnels"
	case cmd == "bans" && fs.NArg() == 1:
		path = "/bans"
	case cmd == "links" && fs.NArg() == 1:
		path = "/links"
	case cmd == "forget" && fs.NArg() == 2:
		method, path = http.MethodPost, "/forget"
		q.Set("sub", linkName(arg))
	case cmd == "flags" && fs.NArg() == 1:
		path = "/flags"
	case cmd == "scan" && fs.NArg() == 1:
		method, path = http.MethodPost, "/scan"
	case cmd == "suspend" && fs.NArg() == 2:
		method, path = http.MethodPost, "/suspend"
		q.Set("sub", linkName(arg))
	case cmd == "unban-user" && fs.NArg() == 2:
		method, path = http.MethodPost, "/unban-user"
		q.Set("login", arg)
	case cmd == "kill" && fs.NArg() == 2:
		method, path = http.MethodPost, "/kill"
		if net.ParseIP(arg) != nil {
			q.Set("ip", arg)
		} else {
			q.Set("sub", arg)
		}
	case (cmd == "ban" || cmd == "unban") && fs.NArg() == 2:
		method, path = http.MethodPost, "/"+cmd
		q.Set("ip", arg)
	default:
		fs.Usage()
		os.Exit(2)
	}

	req, err := http.NewRequest(method, "http://"+*addr+path+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	if *token != "" {
		req.Header.Set("Authorization", "Bearer "+*token)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach admin API at %s (is the server running with --admin?): %w", *addr, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return errors.New(string(body))
	}
	os.Stdout.Write(body)
	return nil
}
