package httpapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keystore"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/merkle"
)

func newTestServer() *Server {
	return NewServer(keystore.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func do(t *testing.T, h http.Handler, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rdr = bytes.NewReader(buf)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 && rec.Header().Get("Content-Type") == "application/json" {
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
	}
	return rec, out
}

func TestHealth(t *testing.T) {
	h := newTestServer().Router()
	rec, body := do(t, h, http.MethodGet, "/health", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200", rec.Code)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field: %v", body["status"])
	}
}

func TestCreateAndGet(t *testing.T) {
	h := newTestServer().Router()

	rec, body := do(t, h, http.MethodPost, "/v1/keys", map[string]string{"agent_id": "a1"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status: got %d want 201", rec.Code)
	}
	pub, _ := body["public_key"].(string)
	if len(pub) != 64 { // 32 bytes hex
		t.Fatalf("public_key hex length: got %d", len(pub))
	}

	rec, body = do(t, h, http.MethodGet, "/v1/keys/a1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status: got %d", rec.Code)
	}
	if body["public_key"] != pub {
		t.Fatal("get returned different public key")
	}
}

func TestCreateMissingField(t *testing.T) {
	h := newTestServer().Router()
	rec, body := do(t, h, http.MethodPost, "/v1/keys", map[string]string{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
	if body["error"] != "missing_field" {
		t.Fatalf("error code: %v", body["error"])
	}
}

func TestCreateBadJSON(t *testing.T) {
	h := newTestServer().Router()
	req := httptest.NewRequest(http.MethodPost, "/v1/keys", bytes.NewReader([]byte("not-json")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d", rec.Code)
	}
}

func TestCreateDuplicate(t *testing.T) {
	h := newTestServer().Router()
	do(t, h, http.MethodPost, "/v1/keys", map[string]string{"agent_id": "dup"})
	rec, body := do(t, h, http.MethodPost, "/v1/keys", map[string]string{"agent_id": "dup"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409", rec.Code)
	}
	if body["error"] != "already_exists" {
		t.Fatalf("error code: %v", body["error"])
	}
}

func TestGetMissing(t *testing.T) {
	h := newTestServer().Router()
	rec, body := do(t, h, http.MethodGet, "/v1/keys/nope", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", rec.Code)
	}
	if body["error"] != "not_found" {
		t.Fatalf("error code: %v", body["error"])
	}
}

func TestList(t *testing.T) {
	h := newTestServer().Router()
	for _, id := range []string{"b", "a"} {
		do(t, h, http.MethodPost, "/v1/keys", map[string]string{"agent_id": id})
	}
	rec, body := do(t, h, http.MethodGet, "/v1/keys", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d", rec.Code)
	}
	ids, _ := body["agent_ids"].([]any)
	if len(ids) != 2 || ids[0] != "a" || ids[1] != "b" {
		t.Fatalf("agent_ids: %v", ids)
	}
}

func TestAgentsCreateAndGetPubKey(t *testing.T) {
	h := newTestServer().Router()

	rec, body := do(t, h, http.MethodPost, "/v1/keys/agents", map[string]string{"agent_id": "agent1"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status: got %d want 201", rec.Code)
	}
	pub, _ := body["public_key"].(string)
	if len(pub) != 64 {
		t.Fatalf("public_key hex length: got %d", len(pub))
	}
	if body["agent_id"] != "agent1" {
		t.Fatalf("agent_id: %v", body["agent_id"])
	}

	rec, body = do(t, h, http.MethodGet, "/v1/keys/agents/agent1/pubkey", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status: got %d want 200", rec.Code)
	}
	if body["public_key"] != pub {
		t.Fatal("get returned different public key")
	}
	if body["agent_id"] != "agent1" {
		t.Fatalf("agent_id: %v", body["agent_id"])
	}
}

func TestAgentsCreateMissingField(t *testing.T) {
	h := newTestServer().Router()
	rec, body := do(t, h, http.MethodPost, "/v1/keys/agents", map[string]string{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
	if body["error"] != "missing_field" {
		t.Fatalf("error code: %v", body["error"])
	}
}

func TestAgentsCreateBadJSON(t *testing.T) {
	h := newTestServer().Router()
	req := httptest.NewRequest(http.MethodPost, "/v1/keys/agents", bytes.NewReader([]byte("not-json")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d", rec.Code)
	}
}

func TestAgentsCreateDuplicate(t *testing.T) {
	h := newTestServer().Router()
	do(t, h, http.MethodPost, "/v1/keys/agents", map[string]string{"agent_id": "dup"})
	rec, body := do(t, h, http.MethodPost, "/v1/keys/agents", map[string]string{"agent_id": "dup"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status: got %d want 409", rec.Code)
	}
	if body["error"] != "already_exists" {
		t.Fatalf("error code: %v", body["error"])
	}
}

func TestGetAgentPubKeyMissing(t *testing.T) {
	h := newTestServer().Router()
	rec, body := do(t, h, http.MethodGet, "/v1/keys/agents/nope/pubkey", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", rec.Code)
	}
	if body["error"] != "not_found" {
		t.Fatalf("error code: %v", body["error"])
	}
}

func TestStatusRecorderForwardsFlush(t *testing.T) {
	// Regression: logRequests wraps the writer in statusRecorder, which
	// previously hid the Flusher and broke /v1/audit/events. Verify that
	// the wrapper still satisfies http.Flusher when constructed over a
	// flushable backing writer.
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec, status: 200}
	if _, ok := any(sr).(http.Flusher); !ok {
		t.Fatal("statusRecorder must implement http.Flusher")
	}
}

func TestMerkleHead(t *testing.T) {
	tree := merkle.New()
	if _, err := tree.Append([]byte("alpha")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := tree.Append([]byte("beta")); err != nil {
		t.Fatalf("append: %v", err)
	}
	srv := NewServer(keystore.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil))).WithMerkleTree(tree)
	rec, body := do(t, srv.Router(), http.MethodGet, "/v1/merkle/head", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	if size, _ := body["size"].(float64); size != 2 {
		t.Fatalf("size: got %v want 2", body["size"])
	}
	root, _ := body["root_hex"].(string)
	if !strings.HasPrefix(root, "0x") {
		t.Fatalf("root_hex must be 0x-prefixed: %q", root)
	}
	wantSize, wantRoot := tree.Snapshot()
	if size, _ := body["size"].(float64); uint64(size) != wantSize {
		t.Fatalf("size mismatch: got %v want %d", body["size"], wantSize)
	}
	if root != "0x"+hex.EncodeToString(wantRoot) {
		t.Fatalf("root mismatch: got %s want 0x%s", root, hex.EncodeToString(wantRoot))
	}
}

func TestMerkleHeadNotMountedWithoutTree(t *testing.T) {
	h := newTestServer().Router()
	rec, _ := do(t, h, http.MethodGet, "/v1/merkle/head", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", rec.Code)
	}
}

func TestCORSAllowed(t *testing.T) {
	srv := NewServer(keystore.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithCORS([]string{"http://localhost:5173"})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("ACAO: got %q", got)
	}
}

func TestCORSPreflight(t *testing.T) {
	srv := NewServer(keystore.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithCORS([]string{"http://localhost:5173"})
	req := httptest.NewRequest(http.MethodOptions, "/v1/keys", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status: got %d want 204", rec.Code)
	}
}

func TestCORSDisallowedOrigin(t *testing.T) {
	srv := NewServer(keystore.NewMemory(), slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithCORS([]string{"http://localhost:5173"})
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	srv.Router().ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO should be empty for disallowed origin, got %q", got)
	}
}

func TestDelete(t *testing.T) {
	h := newTestServer().Router()
	do(t, h, http.MethodPost, "/v1/keys", map[string]string{"agent_id": "rm"})

	rec, _ := do(t, h, http.MethodDelete, "/v1/keys/rm", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status: got %d want 204", rec.Code)
	}
	rec, _ = do(t, h, http.MethodDelete, "/v1/keys/rm", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete missing status: got %d want 404", rec.Code)
	}
}
