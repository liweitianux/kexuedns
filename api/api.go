// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024-2025 Aaron LI
//
// Kexue DNS API handlers.
//

package api

import (
	"net/http"

	"kexuedns/config"
	"kexuedns/dns"
	"kexuedns/log"
)

type Handler struct {
	forwarder *dns.Forwarder
	config    *config.Config
	myip      *config.MyIP
	mux       *http.ServeMux
}

func New() *Handler {
	h := &Handler{
		forwarder: &dns.Forwarder{},
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

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

// Start the forwarder.
// Input: nil
// Return:
// - 500: error
// - 204: success
func (h *Handler) start(w http.ResponseWriter, r *http.Request) {
	if r := h.config.Resolver; r == nil {
		log.Warnf("no resolver configured yet")
	} else {
		resolver := &dns.ResolverExport{
			Name:       r.Name,
			Protocol:   r.Protocol,
			Address:    r.Address,
			ServerName: r.ServerName,
		}
		if err := h.forwarder.Router.SetResolver(resolver); err != nil {
			log.Warnf("failed to set resolver: %+v, error: %v", r, err)
		} else {
			log.Infof("set default resolver: %+v", r)
		}
	}

	err := h.forwarder.SetListen(h.config.ListenAddress)
	if err != nil {
		log.Errorf("failed to set UDP+TCP listen: %v", err)
		http.Error(w, "set UDP+TCP listen failure: "+err.Error(),
			http.StatusInternalServerError)
		return
	}

	if dot := h.config.ListenDoT; dot != nil {
		err := h.forwarder.SetListenDoT(dot.Address,
			dot.CertFile.Path(), dot.KeyFile.Path())
		if err != nil {
			log.Errorf("failed to set DoT listen: %v", err)
			http.Error(w, "set DoT listen failure: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
	}

	if doh := h.config.ListenDoH; doh != nil {
		err := h.forwarder.SetListenDoH(doh.Address,
			doh.CertFile.Path(), doh.KeyFile.Path())
		if err != nil {
			log.Errorf("failed to set DoH listen: %v", err)
			http.Error(w, "set DoH listen failure: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
	}

	if err := h.forwarder.Start(); err != nil {
		http.Error(w, "start failure: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Stop the forwarder.
// Input: nil
// Return:
// - 204: success
func (h *Handler) stop(w http.ResponseWriter, r *http.Request) {
	h.forwarder.Stop()
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) getVersion(w http.ResponseWriter, r *http.Request) {
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
