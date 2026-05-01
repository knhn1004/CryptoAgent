// Package merklehttp exposes the Verifier over HTTP. The keyservice
// (cmd/keyserver) can mount this handler at any path; for now, callers
// wire it themselves so package merkle stays decoupled from chi.
package merklehttp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/merkle"
)

type request struct {
	HistoricalRoot string `json:"historical_root"`
	HistoricalSize uint64 `json:"historical_size"`
}

// Handler returns POST /v1/merkle/verify. The response body is always a
// VerificationReport; status 200 on consistent, 422 on divergence,
// 400 on malformed input.
func Handler(v *merkle.Verifier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "message": err.Error()})
			return
		}
		root, err := hex.DecodeString(req.HistoricalRoot)
		if err != nil || len(root) != merkle.HashSize {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_root", "message": "historical_root must be 32-byte hex"})
			return
		}
		report, verr := v.VerifyHistoricalRoot(root, req.HistoricalSize)
		status := http.StatusOK
		if verr != nil {
			if errors.Is(verr, merkle.ErrSizeRegression) {
				status = http.StatusUnprocessableEntity
			} else {
				status = http.StatusUnprocessableEntity
			}
		}
		writeJSON(w, status, report)
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
