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
