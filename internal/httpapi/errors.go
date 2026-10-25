package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	bolt "github.com/litemd-hq/litemd/internal/bolt"
)

const maxJSONBody = 8 << 10 // 8 KiB

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	ServerEntry any    `json:"server_entry,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeErrorWith(w, status, code, message, nil)
}

// writeErrorWith emits an error envelope that may include the current server
// entry, so clients can resolve a conflict without another round trip.
func writeErrorWith(w http.ResponseWriter, status int, code, message string, entry any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{Error: errorBody{
		Code: code, Message: message, ServerEntry: entry,
	}})
}

func writeConflict(w http.ResponseWriter, entry any, message string) {
	writeErrorWith(w, http.StatusConflict, "conflict", message, entry)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

func storeNotFound(err error) bool { return errors.Is(err, bolt.ErrNotFound) }
