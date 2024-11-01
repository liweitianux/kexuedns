package api

import (
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
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "500 internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
	w.Write([]byte("\n"))
}
