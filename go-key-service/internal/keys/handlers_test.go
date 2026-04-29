package keys

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func newTestServer(t *testing.T) (*httptest.Server, Store) {
	t.Helper()
	store := NewMemoryStore()
	r := mux.NewRouter()
	RegisterRoutes(r, store)
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, store
}

func postRegister(t *testing.T, srv *httptest.Server, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(srv.URL+"/agents", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /agents: %v", err)
	}
	return resp
}

func decodeAgent(t *testing.T, resp *http.Response) agentResponse {
	t.Helper()
	defer resp.Body.Close()
	var a agentResponse
	if err := json.NewDecoder(resp.Body).Decode(&a); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return a
}

func TestPostAgents_CreatesKey(t *testing.T) {
	srv, _ := newTestServer(t)
	resp := postRegister(t, srv, `{"agent_id":"agent-001"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201", resp.StatusCode)
	}
	got := decodeAgent(t, resp)
	if got.AgentID != "agent-001" {
		t.Fatalf("agent_id = %q, want agent-001", got.AgentID)
	}
	pub, err := hex.DecodeString(got.PublicKey)
	if err != nil {
		t.Fatalf("public_key not hex: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public_key length = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

func TestPostAgents_RejectsMissingAgentID(t *testing.T) {
	srv, _ := newTestServer(t)
	resp := postRegister(t, srv, `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPostAgents_RejectsInvalidJSON(t *testing.T) {
	srv, _ := newTestServer(t)
	resp := postRegister(t, srv, `not json`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestPostAgents_RejectsReRegistration(t *testing.T) {
	srv, _ := newTestServer(t)
	first := postRegister(t, srv, `{"agent_id":"agent-001"}`)
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first status = %d, want 201", first.StatusCode)
	}
	firstBody := decodeAgent(t, first)

	second := postRegister(t, srv, `{"agent_id":"agent-001"}`)
	if second.StatusCode != http.StatusConflict {
		t.Fatalf("second status = %d, want 409", second.StatusCode)
	}
	second.Body.Close()

	// Original key must remain intact.
	resp, err := http.Get(srv.URL + "/agents/agent-001/pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status = %d, want 200", resp.StatusCode)
	}
	got := decodeAgent(t, resp)
	if got.PublicKey != firstBody.PublicKey {
		t.Fatal("re-registration rejection mutated stored public key")
	}
}

func TestGetPubkey_ReturnsStoredKey(t *testing.T) {
	srv, _ := newTestServer(t)
	created := decodeAgent(t, postRegister(t, srv, `{"agent_id":"agent-xyz"}`))

	resp, err := http.Get(srv.URL + "/agents/agent-xyz/pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got := decodeAgent(t, resp)
	if got.PublicKey != created.PublicKey {
		t.Fatalf("public_key mismatch: got %q want %q", got.PublicKey, created.PublicKey)
	}
}

func TestGetPubkey_NotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	resp, err := http.Get(srv.URL + "/agents/missing/pubkey")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestPostAgents_ContentTypeJSON(t *testing.T) {
	srv, _ := newTestServer(t)
	resp := postRegister(t, srv, `{"agent_id":"agent-001"}`)
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
}
