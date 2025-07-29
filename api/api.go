// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// Kexue DNS API handlers.
//

package api

import (
	"net/http"
	"net/netip"

	"kexuedns/config"
	"kexuedns/dns"
	"kexuedns/log"
)

type ApiHandler struct {
	forwarder *dns.Forwarder
	config    *config.Config
	myip      *config.MyIP
	mux       *http.ServeMux
}

func NewApiHandler() *ApiHandler {
	h := &ApiHandler{
		forwarder: dns.NewForwarder(),
		config:    config.Get(),
		myip:      config.GetMyIP(),
		mux:       http.NewServeMux(),
	}
	// NOTE: Patterns require Go 1.22.0+
	h.mux.HandleFunc("POST /start", h.start)
	h.mux.HandleFunc("POST /stop", h.stop)
	h.mux.HandleFunc("GET /version", h.getVersion)
	return h
}

func (h *ApiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// Start the forwarder.
// Input: nil
// Return:
// - 500: error
// - 204: success
func (h *ApiHandler) start(w http.ResponseWriter, r *http.Request) {
	if r := h.config.Resolver; r == nil {
		log.Warnf("no resolver configured yet")
	} else {
		resolver, err := dns.NewResolver(r.IP, r.Port, r.Hostname)
		if err != nil {
			log.Warnf("failed to create resolver: %+v, error: %v", r, err)
		} else {
			h.forwarder.SetResolver(resolver)
			log.Infof("set resolver: %+v", r)
		}
	}

	addr, err := netip.ParseAddr(h.config.ListenAddr)
	if err != nil {
		log.Errorf("invalid listen address: %s, error: %v", h.config.ListenAddr, err)
		http.Error(w, "invalid address: "+err.Error(), http.StatusInternalServerError)
		return
	}

	addrport := netip.AddrPortFrom(addr, h.config.ListenPort)
	if err := h.forwarder.Start(addrport.String()); err != nil {
		http.Error(w, "start failure: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Stop the forwarder.
// Input: nil
// Return:
// - 204: success
func (h *ApiHandler) stop(w http.ResponseWriter, r *http.Request) {
	h.forwarder.Stop()
	w.WriteHeader(http.StatusNoContent)
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
