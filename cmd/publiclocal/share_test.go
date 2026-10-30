package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShareHandler(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "report.pdf"), []byte("%PDF-1.4 fake"), 0o644)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("SECRET=1"), 0o644)
	os.MkdirAll(filepath.Join(dir, "assets"), 0o755)
	os.WriteFile(filepath.Join(dir, "assets", "a.css"), []byte("body{}"), 0o644)

	get := func(h http.Handler, path string) (int, string) {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		b, _ := io.ReadAll(rr.Result().Body)
		return rr.Code, string(b)
	}

	folder := shareHandler(dir, true)
	code, body := get(folder, "/")
	if code != 200 || !strings.Contains(body, "report.pdf") || !strings.Contains(body, "assets/") || strings.Contains(body, ".env") {
		t.Fatalf("listing: %d %s", code, body)
	}
	if code, _ := get(folder, "/.env"); code != 404 {
		t.Fatalf("dotfile served: %d", code)
	}
	if code, body := get(folder, "/assets/a.css"); code != 200 || body != "body{}" {
		t.Fatalf("file in subfolder: %d %q", code, body)
	}
	if code, body := get(folder, "/assets/"); code != 200 || !strings.Contains(body, "a.css") || !strings.Contains(body, "../") {
		t.Fatalf("subfolder listing: %d", code)
	}

	file := shareHandler(filepath.Join(dir, "report.pdf"), false)
	if code, body := get(file, "/"); code != 200 || !strings.HasPrefix(body, "%PDF") {
		t.Fatalf("single file at /: %d %q", code, body)
	}
	if code, _ := get(file, "/other"); code != 404 {
		t.Fatalf("single file elsewhere: %d", code)
	}
}
