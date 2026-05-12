// Package auditloghttp exposes the audit-log Pipeline over HTTP. The
// keyserver mounts this handler under /v1/audit so the dashboard can
// submit signed actions and tail the resulting indexed events.
package auditloghttp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/auditlog"
)

// Handler returns an http.Handler exposing the append and event-stream
// endpoints for the given pipeline.
func Handler(p *auditlog.Pipeline, logger *slog.Logger) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &handler{p: p, logger: logger}
	r := chi.NewRouter()
	r.Post("/v1/audit/append", h.append)
	r.Get("/v1/audit/events", h.stream)
	return r
}

// Mount attaches the audit endpoints onto an existing chi.Router so the
// keyserver can keep all v1 routes on a single router.
func Mount(r chi.Router, p *auditlog.Pipeline, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	h := &handler{p: p, logger: logger}
	r.Post("/v1/audit/append", h.append)
	r.Get("/v1/audit/events", h.stream)
}

type handler struct {
	p      *auditlog.Pipeline
	logger *slog.Logger
}

type appendRequest struct {
	Action    *action.Action `json:"action"`
	Signature string         `json:"signature"`
}

type appendResponse struct {
	auditlog.Event
	Idempotent bool `json:"idempotent"`
}

// MarshalJSON merges the embedded Event's hex-encoded fields with the
// idempotent flag in a single object.
func (r appendResponse) MarshalJSON() ([]byte, error) {
	b, err := json.Marshal(r.Event)
	if err != nil {
		return nil, err
	}
	// Splice in idempotent before the closing brace.
	if len(b) < 2 || b[len(b)-1] != '}' {
		return nil, fmt.Errorf("auditloghttp: unexpected event json: %s", b)
	}
	tail := fmt.Sprintf(`,"idempotent":%t}`, r.Idempotent)
	return append(b[:len(b)-1], tail...), nil
}

func (h *handler) append(w http.ResponseWriter, r *http.Request) {
	var req appendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.Action == nil {
		writeError(w, http.StatusBadRequest, "missing_field", "action is required")
		return
	}
	sig, err := hex.DecodeString(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_signature_hex", err.Error())
		return
	}

	ev, fresh, err := h.p.Submit(r.Context(), req.Action, sig)
	if err != nil {
		h.writePipelineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, appendResponse{Event: *ev, Idempotent: !fresh})
}

func (h *handler) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "no_flush", "streaming unsupported")
		return
	}

	since := uint64(0)
	if v := r.URL.Query().Get("since"); v != "" {
		parsed, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_since", err.Error())
			return
		}
		since = parsed
	}

	ch, cancel := h.p.Subscribe()
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Replay backlog first. Track the highest delivered Seq so we can
	// suppress duplicates that may have arrived between EventsSince and
	// Subscribe. Seq is monotonic across both appended and rejected
	// events, unlike LeafIndex which only applies to successful appends.
	lastSent := uint64(0)
	lastSentSet := false
	for _, ev := range h.p.AllEventsSince(since) {
		if err := writeSSE(w, ev); err != nil {
			return
		}
		lastSent = ev.Seq
		lastSentSet = true
	}
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if lastSentSet && ev.Seq <= lastSent {
				continue
			}
			if err := writeSSE(w, ev); err != nil {
				return
			}
			lastSent = ev.Seq
			lastSentSet = true
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, ev auditlog.Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "id: %d\ndata: %s\n\n", ev.Seq, b); err != nil {
		return err
	}
	return nil
}

func (h *handler) writePipelineError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auditlog.ErrUnknownAgent):
		writeError(w, http.StatusNotFound, "unknown_agent", err.Error())
	case errors.Is(err, auditlog.ErrInvalidSignature):
		writeError(w, http.StatusUnauthorized, "invalid_signature", err.Error())
	case errors.Is(err, auditlog.ErrSchemaVersion):
		writeError(w, http.StatusUnprocessableEntity, "schema_version", err.Error())
	case errors.Is(err, auditlog.ErrTimestampSkew):
		writeError(w, http.StatusUnprocessableEntity, "timestamp_skew", err.Error())
	case errors.Is(err, action.ErrEmptyField), errors.Is(err, action.ErrNonceShape):
		writeError(w, http.StatusBadRequest, "invalid_action", err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusRequestTimeout, "canceled", err.Error())
	default:
		h.logger.Error("auditlog submit", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}
