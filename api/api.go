// SPDX-License-Identifier: MIT
//
// Kexue DNS API handlers.
//

package api

import (
	"net/http"

	"kexuedns/config"
	"kexuedns/dns"
)

type ApiHandler struct {
	forwarder *dns.Forwarder
	config    *config.Config
	myip      *config.MyIP
	mux       *http.ServeMux
}

func NewApiHandler(forwarder *dns.Forwarder) *ApiHandler {
	h := &ApiHandler{
		forwarder: forwarder,
		config:    config.Get(),
		myip:      config.GetMyIP(),
		mux:       http.NewServeMux(),
	}
	// NOTE: Patterns require Go 1.22.0+
	h.mux.HandleFunc("GET /version", h.getVersion)
	h.mux.HandleFunc("/", h.handleIndex)
	return h
}

func (h *ApiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *ApiHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("yo\n"))
}

func (h *ApiHandler) getVersion(w http.ResponseWriter, r *http.Request) {
	vi := config.GetVersion()
	var resp = struct {
		Version string `json:"version"`
		Date    string `json:"date"`
	}{
		Version: vi.Version,
		Date:    vi.Date,
	}
	writeJSON(w, &resp)
}
