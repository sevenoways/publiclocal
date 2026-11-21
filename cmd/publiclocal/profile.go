package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Profiles are saved flag sets, so `publiclocal http --profile demo` stands
// for a long command. They live in publiclocal.json in the current folder
// (good for a team repository) or in profiles.json in the config folder.
//
//	{"profiles": {"demo": {"flags": ["--password", "s3cret", "--expires", "2h"], "args": ["3000"]}}}

type profile struct {
	Flags []string `json:"flags"`
	Args  []string `json:"args,omitempty"`

	project bool // from publiclocal.json in the current folder, which may come from a cloned repository
}

// projectFlags are the flags a project's publiclocal.json may set. Anything
// that changes where the client connects, what it publishes or what it runs
// on this computer stays out: a cloned repository must not be able to send
// your token elsewhere, serve your files or open things.
var projectFlags = map[string]bool{
	"password": true, "expires": true, "max-visits": true, "note": true, "cors": true, "qr": true, "quiet": true,
	"host-header": true, "allow-ip": true, "allow-github": true, "header": true, "rewrite": true, "block": true,
	"latency": true, "fail": true, "feedback": true, "live": true, "verify-strict": true, "status": true, "body": true,
}

// checkProjectProfile refuses project profiles that reach beyond link options.
func checkProjectProfile(name string, p profile) error {
	for i := 0; i < len(p.Flags); i++ {
		f := p.Flags[i]
		if !strings.HasPrefix(f, "-") {
			return fmt.Errorf("profile %q: %q is not a flag; put ports in \"args\"", name, f)
		}
		k := strings.TrimLeft(f, "-")
		if j := strings.Index(k, "="); j >= 0 {
			k = k[:j]
		} else if !boolFlags[k] {
			i++ // skip the value
		}
		if !projectFlags[k] {
			return fmt.Errorf("profile %q in publiclocal.json may not set --%s; move it to %s, which only you control", name, k, userProfilesHint())
		}
	}
	for _, a := range p.Args {
		if !localPortRE.MatchString(a) {
			return fmt.Errorf("profile %q in publiclocal.json: args may only be local ports (got %q)", name, a)
		}
	}
	return nil
}

var localPortRE = regexp.MustCompile(`^((localhost|127\.[0-9.]+|\[::1\]):)?[0-9]{1,5}$`)

func userProfilesHint() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "publiclocal", "profiles.json")
	}
	return "profiles.json in the config folder"
}

type profileFile struct {
	Profiles map[string]profile `json:"profiles"`
}

// profilePaths lists where profiles are read from, nearest first.
func profilePaths() []string {
	var out []string
	if dir, err := os.Getwd(); err == nil {
		out = append(out, filepath.Join(dir, "publiclocal.json"))
	}
	if dir, err := os.UserConfigDir(); err == nil {
		out = append(out, filepath.Join(dir, "publiclocal", "profiles.json"))
	}
	return out
}

func loadProfiles() (map[string]profile, []string, error) {
	all := map[string]profile{}
	var found []string
	for i, p := range profilePaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var f profileFile
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, nil, fmt.Errorf("%s: %v", p, err)
		}
		found = append(found, p)
		for name, pr := range f.Profiles {
			if _, dup := all[name]; !dup { // the nearer file wins
				pr.project = i == 0
				all[name] = pr
			}
		}
	}
	return all, found, nil
}

// applyProfile looks for --profile NAME in args and splices that profile's
// flags in front of the rest, so flags given on the command line still win.
// Its args are used when the command line gives none.
func applyProfile(args []string) ([]string, error) {
	name, rest := "", make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--profile" || a == "-profile":
			if i+1 >= len(args) {
				return nil, errors.New("--profile needs a name")
			}
			name, i = args[i+1], i+1
		case strings.HasPrefix(a, "--profile="), strings.HasPrefix(a, "-profile="):
			name = a[strings.Index(a, "=")+1:]
		default:
			rest = append(rest, a)
		}
	}
	if name == "" {
		return args, nil
	}
	profiles, _, err := loadProfiles()
	if err != nil {
		return nil, err
	}
	p, ok := profiles[name]
	if !ok {
		return nil, fmt.Errorf("no profile %q; run publiclocal profiles to see them", name)
	}
	if p.project {
		if err := checkProjectProfile(name, p); err != nil {
			return nil, err
		}
	} else if len(p.Flags) > 0 && !strings.HasPrefix(p.Flags[0], "-") {
		return nil, fmt.Errorf("profile %q: flags must start with -, put ports and paths in \"args\"", name)
	}
	out := append(append([]string{}, p.Flags...), rest...)
	if !hasPositional(rest) {
		out = append(out, p.Args...)
	}
	fmt.Fprintf(os.Stderr, "Profile %s: %s\n", name, strings.Join(append(append([]string{}, maskFlags(p.Flags)...), p.Args...), " "))
	return out, nil
}

// hasPositional reports whether a command line has anything after its flags.
// Boolean flags take no value, so only known value flags consume the next word.
func hasPositional(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			return true
		}
		if !strings.Contains(a, "=") && !boolFlags[strings.TrimLeft(a, "-")] {
			i++ // value flag: skip its value
		}
	}
	return false
}

// boolFlags are the tunnel flags that take no value.
var boolFlags = map[string]bool{"tls": true, "insecure-skip-verify": true, "new": true, "qr": true, "quiet": true, "debug": true, "open": true, "copy": true, "cors": true, "verify-strict": true, "feedback": true, "live": true}

func runProfiles(args []string) error {
	profiles, files, err := loadProfiles()
	if err != nil {
		return err
	}
	if len(profiles) == 0 {
		fmt.Println("No profiles. Create publiclocal.json in your project, for example:")
		fmt.Println(`{"profiles": {"demo": {"flags": ["--password", "s3cret", "--expires", "2h", "--note", "staging build"], "args": ["3000"]}}}`)
		fmt.Println("Then: publiclocal http --profile demo")
		return nil
	}
	fmt.Println("Profiles from", strings.Join(files, " and "))
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := profiles[n]
		fmt.Printf("  %-16s %s\n", n, strings.Join(append(append([]string{}, maskFlags(p.Flags)...), p.Args...), " "))
	}
	return nil
}

// secretFlags carry secrets and are hidden in listings.
var secretFlags = map[string]bool{"password": true, "token": true, "verify": true, "account": true}

// maskFlags hides secret values in listings.
func maskFlags(flags []string) []string {
	out := append([]string{}, flags...)
	for i, f := range out {
		k := strings.TrimLeft(f, "-")
		if j := strings.Index(k, "="); j >= 0 {
			if secretFlags[k[:j]] && strings.HasPrefix(f, "-") {
				out[i] = f[:strings.Index(f, "=")+1] + "***"
			}
		} else if secretFlags[k] && strings.HasPrefix(f, "-") && i+1 < len(out) {
			out[i+1] = "***"
		}
	}
	return out
}
