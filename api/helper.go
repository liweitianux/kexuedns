// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 Aaron LI
//
// API helpers.
//

package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

var (
	errContentType     = errors.New("Content-Type missing or invalid")
	errBodyInvalidJSON = errors.New("body invalid JSON")
)

func readJSON(r *http.Request, v any) error {
	mediaType := ""
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	}
	if mediaType != "application/json" {
		return errContentType
	}

	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return errBodyInvalidJSON
	}

	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		http.Error(w, "500 internal server error: "+err.Error(),
			http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}
