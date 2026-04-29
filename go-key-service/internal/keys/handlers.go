package keys

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
)

type registerRequest struct {
	AgentID string `json:"agent_id"`
}

type agentResponse struct {
	AgentID   string `json:"agent_id"`
	PublicKey string `json:"public_key"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// RegisterRoutes attaches /agents endpoints to r, backed by store.
func RegisterRoutes(r *mux.Router, store Store) {
	r.HandleFunc("/agents", registerHandler(store)).Methods(http.MethodPost)
	r.HandleFunc("/agents/{id}/pubkey", pubKeyHandler(store)).Methods(http.MethodGet)
}

func registerHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req registerRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if req.AgentID == "" {
			writeError(w, http.StatusBadRequest, "agent_id is required")
			return
		}
		pub, err := store.Create(req.AgentID)
		if err != nil {
			switch {
			case errors.Is(err, ErrAgentExists):
				writeError(w, http.StatusConflict, "agent already registered")
			default:
				writeError(w, http.StatusInternalServerError, "failed to create keypair")
			}
			return
		}
		writeJSON(w, http.StatusCreated, agentResponse{
			AgentID:   req.AgentID,
			PublicKey: hex.EncodeToString(pub),
		})
	}
}

func pubKeyHandler(store Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		pub, err := store.PublicKey(id)
		if err != nil {
			if errors.Is(err, ErrAgentNotFound) {
				writeError(w, http.StatusNotFound, "agent not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "lookup failed")
			return
		}
		writeJSON(w, http.StatusOK, agentResponse{
			AgentID:   id,
			PublicKey: hex.EncodeToString(pub),
		})
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}
