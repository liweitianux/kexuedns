// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 Aaron LI
//
// Embed assets of the webui.
//

package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed index.html static
var content embed.FS

func ServeStatic() http.Handler {
	staticFS, err := fs.Sub(content, "static")
	if err != nil {
		panic(err)
	}
	return http.FileServer(http.FS(staticFS))
}

func ServeIndex(w http.ResponseWriter, r *http.Request) {
	data, err := content.ReadFile("index.html")
	if err != nil {
		http.Error(w, "500 internal server error: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
	w.Write(data)
}
