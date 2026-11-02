package main

import (
	"errors"
	"fmt"
	"os"
)

const domainsUsage = `Usage: publiclocal domains <command>

  add <host>      add a custom name, e.g. demo.example.com, and show the DNS records to set
  verify <host>   check the DNS records; the name can be used once it is verified
  list            your custom names
  remove <host>   stop using a name

Then: publiclocal http --domain demo.example.com 3000
`

// runDomains manages custom domains for a signed-in user.
func runDomains(args []string) error {
	fs, srv, useTLS := accountFlags("domains")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), domainsUsage)
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	api := newAPI(resolveServer(*srv), *useTLS)
	if api.token == "" {
		return errors.New("custom domains need an account; run publiclocal login")
	}
	cmd, host := fs.Arg(0), fs.Arg(1)
	if cmd != "list" && host == "" {
		fs.Usage()
		os.Exit(2)
	}
	type record struct {
		Host     string
		TXTName  string `json:"txt_name"`
		TXTValue string `json:"txt_value"`
		CNAME    string
		Verified bool
		Link     string
	}
	switch cmd {
	case "add":
		var out record
		if err := api.call("POST", "/api/domains", map[string]string{"host": host}, &out); err != nil {
			return err
		}
		fmt.Printf("Add these two DNS records for %s:\n\n", out.Host)
		fmt.Printf("  %-28s CNAME  %s\n", out.Host+".", out.CNAME+".")
		fmt.Printf("  %-28s TXT    \"%s\"\n\n", out.TXTName+".", out.TXTValue)
		fmt.Printf("Then run: publiclocal domains verify %s\n", out.Host)
		fmt.Println("If the name is proxied through Cloudflare, switch the proxy off (grey cloud) so certificates can be issued.")
	case "verify":
		var out record
		if err := api.call("POST", "/api/domains/verify", map[string]string{"host": host}, &out); err != nil {
			return err
		}
		fmt.Printf("%s is verified. Use it with: publiclocal http --domain %s 3000\n", out.Host, out.Host)
	case "remove":
		if err := api.call("POST", "/api/domains/remove", map[string]string{"host": host}, nil); err != nil {
			return err
		}
		fmt.Println("Removed", host)
	case "list":
		var out struct{ Domains []record }
		if err := api.call("GET", "/api/domains", nil, &out); err != nil {
			return err
		}
		if len(out.Domains) == 0 {
			fmt.Println("No custom domains. Add one with: publiclocal domains add demo.example.com")
			return nil
		}
		for _, d := range out.Domains {
			state := "not verified; run publiclocal domains verify " + d.Host
			if d.Verified {
				state = "verified"
				if d.Link != "" {
					state += ", last used by " + d.Link
				}
			}
			fmt.Printf("  %-36s %s\n", d.Host, state)
		}
	default:
		fs.Usage()
		os.Exit(2)
	}
	return nil
}
