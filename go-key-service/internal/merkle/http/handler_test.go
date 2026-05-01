package merklehttp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/merkle"
)

func TestVerifyOK(t *testing.T) {
	tr := merkle.New()
	for i := 0; i < 8; i++ {
		tr.Append([]byte{byte(i)})
	}
	hist, _ := tr.RootAt(3)
	body, _ := json.Marshal(map[string]any{
		"historical_root": hex.EncodeToString(hist),
		"historical_size": 3,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/merkle/verify", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	Handler(merkle.NewVerifier(tr)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200, body=%s", rec.Code, rec.Body.String())
	}
	var out merkle.VerificationReport
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK {
		t.Fatalf("expected OK, got %+v", out)
	}
}

func TestVerifyDivergence(t *testing.T) {
	tr := merkle.New()
	for i := 0; i < 8; i++ {
		tr.Append([]byte{byte(i)})
	}
	wrong := bytes.Repeat([]byte{0xAA}, merkle.HashSize)
	body, _ := json.Marshal(map[string]any{
		"historical_root": hex.EncodeToString(wrong),
		"historical_size": 4,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/merkle/verify", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	Handler(merkle.NewVerifier(tr)).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status: got %d want 422", rec.Code)
	}
}

func TestVerifyBadJSON(t *testing.T) {
	tr := merkle.New()
	req := httptest.NewRequest(http.MethodPost, "/v1/merkle/verify", bytes.NewReader([]byte("garbage")))
	rec := httptest.NewRecorder()
	Handler(merkle.NewVerifier(tr)).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
}

func TestVerifyBadRoot(t *testing.T) {
	tr := merkle.New()
	body, _ := json.Marshal(map[string]any{
		"historical_root": "not-hex",
		"historical_size": 0,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/merkle/verify", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	Handler(merkle.NewVerifier(tr)).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", rec.Code)
	}
}

func TestVerifyMethodNotAllowed(t *testing.T) {
	tr := merkle.New()
	req := httptest.NewRequest(http.MethodGet, "/v1/merkle/verify", nil)
	rec := httptest.NewRecorder()
	Handler(merkle.NewVerifier(tr)).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405", rec.Code)
	}
}
