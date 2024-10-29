// SPDX-License-Identifier: MIT
//
// Embed assets of the webui.
//

package ui

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"

	"kexuedns/log"
)

//go:embed index.html static template/*.tmpl
var content embed.FS

var templates *template.Template

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
		http.Error(w, fmt.Sprintf("500 internal server error: %v", err),
			http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func GetTemplate(name string) *template.Template {
	if templates == nil {
		templates = template.Must(template.ParseFS(content, "template/*.tmpl"))
		tt := []string{}
		for _, t := range templates.Templates() {
			tt = append(tt, t.Name())
		}
		log.Infof("parsed templates: %+v", tt)
	}

	return templates.Lookup(name)
}
