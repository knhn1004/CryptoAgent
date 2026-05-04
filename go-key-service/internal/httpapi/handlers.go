// Package httpapi exposes the keystore over JSON HTTP.
package httpapi

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/anchor"
	anchorhttp "github.com/knhn1004/CryptoAgent/go-key-service/internal/anchor/http"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/auditlog"
	auditloghttp "github.com/knhn1004/CryptoAgent/go-key-service/internal/auditlog/http"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/capability"
	capabilityhttp "github.com/knhn1004/CryptoAgent/go-key-service/internal/capability/http"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keystore"
)

type Server struct {
	store       keystore.KeyStore
	pipeline    *auditlog.Pipeline
	capability  *capability.Service
	anchorStore *anchor.LatestStore
	logger      *slog.Logger
}

func NewServer(store keystore.KeyStore, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{store: store, logger: logger}
}

// WithAuditPipeline mounts the audit-log endpoints on the same router as
// the key endpoints. Pass nil to disable; it's optional so existing
// callers (and tests) keep working.
func (s *Server) WithAuditPipeline(p *auditlog.Pipeline) *Server {
	s.pipeline = p
	return s
}

// WithCapability mounts the capability (token) endpoints on the same
// router. Optional; tests that don't need tokens can omit this.
func (s *Server) WithCapability(c *capability.Service) *Server {
	s.capability = c
	return s
}

// WithAnchor mounts the on-chain anchor indexer endpoints. Optional; the
// keyserver runs fine without it for setups that don't anchor on-chain.
func (s *Server) WithAnchor(latest *anchor.LatestStore) *Server {
	s.anchorStore = latest
	return s
}

func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(s.logRequests)
	r.Get("/health", s.handleHealth)
	r.Route("/v1/keys", func(r chi.Router) {
		r.Get("/", s.handleList)
		r.Post("/", s.handleCreate)
		r.Post("/agents", s.handleAgents)
		r.Get("/agents/{agentID}/pubkey", s.handleGetAgentPubKey)
		r.Get("/{agentID}", s.handleGet)
		r.Delete("/{agentID}", s.handleDelete)
	})
	if s.pipeline != nil {
		auditloghttp.Mount(r, s.pipeline, s.logger)
	}
	if s.capability != nil {
		capabilityhttp.Mount(r, s.capability, s.logger)
	}
	if s.anchorStore != nil {
		anchorhttp.Mount(r, s.anchorStore, s.logger)
	}
	return r
}

type errorEnvelope struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

type keyResponse struct {
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"`
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"schema_version": action.SchemaVersion,
	})
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if body.AgentID == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "agent_id is required")
		return
	}
	pub, err := s.store.Create(r.Context(), body.AgentID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, keyResponse{
		AgentID:   body.AgentID,
		PublicKey: hex.EncodeToString(pub),
	})
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "agentID")
	pub, _, err := s.store.Get(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keyResponse{
		AgentID:   id,
		PublicKey: hex.EncodeToString(pub),
	})
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	ids, err := s.store.List(r.Context())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_ids": ids})
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "agentID")
	if err := s.store.Delete(r.Context(), id); err != nil {
		s.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if body.AgentID == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "agent_id is required")
		return
	}
	pub, err := s.store.Create(r.Context(), body.AgentID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, keyResponse{
		AgentID:   body.AgentID,
		PublicKey: hex.EncodeToString(pub),
	})
}

func (s *Server) handleGetAgentPubKey(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "agentID")
	pub, _, err := s.store.Get(r.Context(), id)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, keyResponse{
		AgentID:   id,
		PublicKey: hex.EncodeToString(pub),
	})
}

func (s *Server) writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, keystore.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, keystore.ErrAlreadyExists):
		writeError(w, http.StatusConflict, "already_exists", err.Error())
	default:
		s.logger.Error("keystore", "err", err)
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errorEnvelope{Error: code, Message: msg})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(s int) {
	sr.status = s
	sr.ResponseWriter.WriteHeader(s)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sr, r)
		s.logger.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", sr.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}
