// Package anchorhttp exposes the on-chain anchor indexer over JSON HTTP.
package anchorhttp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/anchor"
)

// Mount attaches the anchor endpoints onto an existing chi.Router.
func Mount(r chi.Router, store *anchor.LatestStore, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	h := &handler{store: store, logger: logger}
	r.Route("/v1/anchor", func(r chi.Router) {
		r.Get("/latest", h.latest)
	})
}

// Handler returns a standalone http.Handler — useful for tests.
func Handler(store *anchor.LatestStore, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()
	Mount(r, store, logger)
	return r
}

type handler struct {
	store  *anchor.LatestStore
	logger *slog.Logger
}

type latestResponse struct {
	ID          uint64 `json:"id"`
	TreeSize    uint64 `json:"tree_size"`
	RootHex     string `json:"root_hex"`
	TimestampMs int64  `json:"timestamp_ms"`
	BlockNumber uint64 `json:"block_number,omitempty"`
	TxHash      string `json:"tx_hash,omitempty"`
}

func (h *handler) latest(w http.ResponseWriter, _ *http.Request) {
	a, err := h.store.Latest()
	if err != nil {
		if errors.Is(err, anchor.ErrNoAnchorYet) {
			writeError(w, http.StatusNotFound, "no_anchor_yet", err.Error())
			return
		}
		h.logger.Error("anchor latest", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, latestResponse{
		ID:          a.ID,
		TreeSize:    a.TreeSize,
		RootHex:     "0x" + hex.EncodeToString(a.Root),
		TimestampMs: a.Timestamp.UnixMilli(),
		BlockNumber: a.BlockNumber,
		TxHash:      a.TxHash,
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}
