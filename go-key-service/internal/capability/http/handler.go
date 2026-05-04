// Package capabilityhttp exposes the capability Service over JSON HTTP.
package capabilityhttp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/capability"
)

// Mount attaches the capability endpoints onto an existing chi.Router.
func Mount(r chi.Router, svc *capability.Service, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	h := &handler{svc: svc, logger: logger}
	r.Route("/v1/tokens", func(r chi.Router) {
		r.Post("/", h.issue)
		r.Post("/verify", h.verify)
		r.Post("/{tokenID}/revoke", h.revoke)
		r.Get("/signing-pubkey", h.signingPubkey)
	})
}

// Handler returns a standalone http.Handler — useful for tests.
func Handler(svc *capability.Service, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()
	Mount(r, svc, logger)
	return r
}

type handler struct {
	svc    *capability.Service
	logger *slog.Logger
}

type issueRequest struct {
	AgentID     string   `json:"agent_id"`
	ActionTypes []string `json:"action_types"`
	Targets     []string `json:"targets"`
	TTLSeconds  int64    `json:"ttl_seconds"`
}

type issueResponse struct {
	TokenID      string `json:"token_id"`
	ClaimsJSON   string `json:"claims_json"`
	SignatureHex string `json:"signature_hex"`
}

func (h *handler) issue(w http.ResponseWriter, r *http.Request) {
	var req issueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.AgentID == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "agent_id is required")
		return
	}
	if req.ActionTypes == nil {
		writeError(w, http.StatusBadRequest, "missing_field", "action_types is required")
		return
	}
	if req.Targets == nil {
		writeError(w, http.StatusBadRequest, "missing_field", "targets is required")
		return
	}
	tok, claims, sig, err := h.svc.Issue(r.Context(), capability.IssueRequest{
		AgentID:     req.AgentID,
		ActionTypes: req.ActionTypes,
		Targets:     req.Targets,
		TTLSeconds:  req.TTLSeconds,
	})
	if err != nil {
		switch {
		case errors.Is(err, capability.ErrInvalidTTL):
			writeError(w, http.StatusBadRequest, "invalid_ttl", err.Error())
		case errors.Is(err, capability.ErrUnknownAgent):
			writeError(w, http.StatusNotFound, "unknown_agent", err.Error())
		default:
			h.logger.Error("token issue", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal error")
		}
		return
	}
	writeJSON(w, http.StatusCreated, issueResponse{
		TokenID:      tok.TokenID,
		ClaimsJSON:   string(claims),
		SignatureHex: hex.EncodeToString(sig),
	})
}

type verifyRequest struct {
	ClaimsJSON   string `json:"claims_json"`
	SignatureHex string `json:"signature_hex"`
	AgentID      string `json:"agent_id"`
	ActionType   string `json:"action_type"`
	Target       string `json:"target"`
}

type verifyResponse struct {
	OK      bool   `json:"ok"`
	TokenID string `json:"token_id"`
}

func (h *handler) verify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.ClaimsJSON == "" || req.SignatureHex == "" || req.AgentID == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "claims_json, signature_hex, agent_id are required")
		return
	}
	sig, err := hex.DecodeString(req.SignatureHex)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_signature_hex", err.Error())
		return
	}
	tok, err := h.svc.Verify(r.Context(), capability.VerifyRequest{
		ClaimsJSON: []byte(req.ClaimsJSON),
		Signature:  sig,
		AgentID:    req.AgentID,
		ActionType: req.ActionType,
		Target:     req.Target,
	})
	if err != nil {
		switch {
		case errors.Is(err, capability.ErrMalformedToken):
			writeError(w, http.StatusBadRequest, "malformed_token", err.Error())
		case errors.Is(err, capability.ErrInvalidSignature):
			writeError(w, http.StatusUnauthorized, "invalid_signature", err.Error())
		case errors.Is(err, capability.ErrExpired):
			writeError(w, http.StatusForbidden, "expired", err.Error())
		case errors.Is(err, capability.ErrRevoked):
			writeError(w, http.StatusForbidden, "revoked", err.Error())
		case errors.Is(err, capability.ErrAgentMismatch):
			writeError(w, http.StatusForbidden, "agent_mismatch", err.Error())
		case errors.Is(err, capability.ErrActionTypeNotAllowed):
			writeError(w, http.StatusForbidden, "action_type_not_allowed", err.Error())
		case errors.Is(err, capability.ErrTargetNotAllowed):
			writeError(w, http.StatusForbidden, "target_not_allowed", err.Error())
		default:
			h.logger.Error("token verify", "err", err)
			writeError(w, http.StatusInternalServerError, "internal", "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{OK: true, TokenID: tok.TokenID})
}

func (h *handler) revoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "tokenID")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "tokenID path param required")
		return
	}
	h.svc.Revoke(r.Context(), id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) signingPubkey(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"public_key_hex": hex.EncodeToString(h.svc.SigningPublicKey()),
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
