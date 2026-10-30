package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// runShare serves a folder or a single file from this computer and opens a
// tunnel to it: `publiclocal share ./build` or `publiclocal share report.pdf`.
func runShare(ctx context.Context, args []string) error {
	fs, o := tunnelFlags("share")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: publiclocal share [flags] <file or folder>")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: shareHandler(path, st.IsDir())}
	go srv.Serve(ln)
	defer srv.Close()

	what := "file " + filepath.Base(path)
	if st.IsDir() {
		what = "folder " + filepath.Base(path) + string(os.PathSeparator)
	}
	fmt.Printf("Sharing %s\n", what)
	return runTunnel(ctx, o, []string{ln.Addr().String()})
}

// shareHandler serves a directory with listings, or a single file at "/".
func shareHandler(path string, isDir bool) http.Handler {
	if !isDir {
		name := filepath.Base(path)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" && r.URL.Path != "/"+name {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Disposition", `inline; filename="`+name+`"`)
			http.ServeFile(w, r, path)
		})
	}
	files := http.FileServer(http.Dir(path))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hide dotfiles, and show a tidier listing than the default.
		for part := range strings.SplitSeq(r.URL.Path, "/") {
			if strings.HasPrefix(part, ".") {
				http.NotFound(w, r)
				return
			}
		}
		full := filepath.Join(path, filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/")))
		if st, err := os.Stat(full); err == nil && st.IsDir() {
			if _, err := os.Stat(filepath.Join(full, "index.html")); err != nil {
				listDir(w, r, full)
				return
			}
		}
		files.ServeHTTP(w, r)
	})
}

type dirEntry struct {
	Name  string
	Size  string
	IsDir bool
}

func listDir(w http.ResponseWriter, r *http.Request, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "cannot read folder", http.StatusInternalServerError)
		return
	}
	var rows []dirEntry
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		row := dirEntry{Name: e.Name(), IsDir: e.IsDir()}
		if info, err := e.Info(); err == nil && !e.IsDir() {
			row.Size = humanSize(info.Size())
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].IsDir != rows[j].IsDir {
			return rows[i].IsDir
		}
		return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	listTmpl.Execute(w, struct {
		Path   string
		Parent bool
		Rows   []dirEntry
	}{r.URL.Path, r.URL.Path != "/", rows})
}

func humanSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(b)/(1<<10))
	}
	return fmt.Sprintf("%d B", b)
}

var errNotDir = errors.New("not a directory")

var listTmpl = template.Must(template.New("list").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>{{.Path}}</title>
<style>
  :root { color-scheme: light dark; --bg:#f6f7f9; --card:#fff; --fg:#1d2330; --muted:#5b6475; --line:#e2e5ea; --accent:#2557e8; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0f1218; --card:#171b23; --fg:#e7eaf0; --muted:#9aa3b2; --line:#2a303b; --accent:#5b8cff; } }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  main { max-width:760px; margin:40px auto; padding:0 16px; }
  h1 { font-size:17px; font-family:ui-monospace,Consolas,monospace; word-break:break-all; margin:0 0 14px; }
  ul { list-style:none; margin:0; padding:0; background:var(--card); border:1px solid var(--line); border-radius:12px; overflow:hidden; }
  li { display:flex; justify-content:space-between; gap:12px; padding:10px 16px; border-bottom:1px solid var(--line); }
  li:last-child { border-bottom:0; } a { color:var(--accent); text-decoration:none; word-break:break-all; } span { color:var(--muted); white-space:nowrap; }
  footer { margin-top:16px; font-size:13px; color:var(--muted); }
</style></head>
<body><main><h1>{{.Path}}</h1><ul>
{{if .Parent}}<li><a href="../">../</a></li>{{end}}
{{range .Rows}}<li><a href="{{.Name}}{{if .IsDir}}/{{end}}">{{.Name}}{{if .IsDir}}/{{end}}</a><span>{{.Size}}</span></li>{{end}}
{{if not .Rows}}<li><span>empty folder</span></li>{{end}}
</ul><footer>Shared with PublicLocal</footer></main></body></html>`))
