package server

import (
	"strings"
	"testing"
)

func TestPhishingReason(t *testing.T) {
	cases := map[string]bool{
		`<form><input type="password"></form> Sign in to Microsoft`:       true,
		`<form><input type=password></form> PayPal`:                       true,
		`<textarea name=words></textarea> Enter your 12-word seed phrase`: true,
		`<form><input type="password"></form> Welcome to my todo app`:     false,
		`<p>We use Google Analytics</p>`:                                  false,
		`<p>Never share your seed phrase.</p>`:                            false, // no form
	}
	for html, want := range cases {
		if got := phishingReason(html) != ""; got != want {
			t.Errorf("%q: flagged=%v, want %v", html, got, want)
		}
	}
}

func TestRandomName(t *testing.T) {
	seen := map[int]bool{}
	for range 2000 {
		n := randomName(6, 8)
		if len(n) < 6 || len(n) > 8 {
			t.Fatalf("%q has length %d", n, len(n))
		}
		for _, c := range n {
			if !strings.ContainsRune(nameAlphabet, c) {
				t.Fatalf("%q contains %q", n, c)
			}
		}
		seen[len(n)] = true
	}
	if len(seen) != 3 {
		t.Fatalf("lengths seen: %v, want 6, 7 and 8", seen)
	}
}
