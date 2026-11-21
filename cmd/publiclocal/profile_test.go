package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestApplyProfile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "publiclocal.json"), []byte(`{"profiles":{"demo":{"flags":["--password","s3cret","--expires","2h"],"args":["3000"]}}}`), 0o600)
	wd, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(wd)

	got, err := applyProfile([]string{"--profile", "demo"})
	if err != nil || !reflect.DeepEqual(got, []string{"--password", "s3cret", "--expires", "2h", "3000"}) {
		t.Fatalf("profile alone: %v %v", got, err)
	}
	// Command-line flags come after, so they win; a given port replaces the profile's.
	got, err = applyProfile([]string{"--qr", "--profile=demo", "--expires", "30m", "8080"})
	if err != nil || !reflect.DeepEqual(got, []string{"--password", "s3cret", "--expires", "2h", "--qr", "--expires", "30m", "8080"}) {
		t.Fatalf("profile with overrides: %v %v", got, err)
	}
	if _, err := applyProfile([]string{"--profile", "nope"}); err == nil {
		t.Fatal("unknown profile should fail")
	}
	if got, _ := applyProfile([]string{"--qr", "3000"}); !reflect.DeepEqual(got, []string{"--qr", "3000"}) {
		t.Fatalf("no profile: %v", got)
	}
	// A project file may not redirect the tunnel, publish files or pick paths.
	for _, bad := range []string{
		`{"profiles":{"x":{"flags":["--server","evil:443"]}}}`,
		`{"profiles":{"x":{"flags":["--mock","/k=C:/secret"]}}}`,
		`{"profiles":{"x":{"flags":["--insecure-skip-verify"]}}}`,
		`{"profiles":{"x":{"flags":["--token=abc"]}}}`,
		`{"profiles":{"x":{"flags":[],"args":["C:/Users/me"]}}}`,
	} {
		os.WriteFile(filepath.Join(dir, "publiclocal.json"), []byte(bad), 0o600)
		if _, err := applyProfile([]string{"--profile", "x"}); err == nil {
			t.Errorf("project profile %s should be refused", bad)
		}
	}
	if m := maskFlags([]string{"--password", "x", "--password=y"}); m[1] != "***" || m[2] != "--password=***" {
		t.Fatalf("mask: %v", m)
	}
	if m := maskFlags([]string{"--token", "t", "--verify=stripe:s", "--note", "n"}); m[1] != "***" || m[2] != "--verify=***" || m[4] != "n" {
		t.Fatalf("mask: %v", m)
	}
}
