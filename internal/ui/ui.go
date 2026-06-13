package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:web
var assets embed.FS

func Handler() http.Handler {
	sub, err := fs.Sub(assets, "web")
	if err != nil {
		panic(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		// Add anti-cache headers for JS/CSS/HTML to ensure UI updates are picked up
		if strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".css") || strings.HasSuffix(path, ".html") {
			w.Header().Set("Cache-Control", "no-cache, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}
		fileServer.ServeHTTP(w, r)
	})
}
