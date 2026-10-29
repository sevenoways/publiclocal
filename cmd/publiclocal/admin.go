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
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `Usage: publiclocal admin [--addr host:port] <command>

  list              connected clients and their tunnels
  kill <sub|ip>     close the session holding a subdomain, or all sessions from an IP
  ban <ip>          ban an IP and close its sessions
  unban <ip>        lift a ban
  bans              list banned IPs
`)
	}
	fs.Parse(args)

	method, path, q := http.MethodGet, "", url.Values{}
	switch cmd, arg := fs.Arg(0), fs.Arg(1); {
	case cmd == "list" && fs.NArg() == 1:
		path = "/tunnels"
	case cmd == "bans" && fs.NArg() == 1:
		path = "/bans"
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
