package capabilityhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/capability"
	capabilityhttp "github.com/knhn1004/CryptoAgent/go-key-service/internal/capability/http"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keystore"
)

func newServer(t *testing.T, now time.Time) (*capability.Service, http.Handler) {
	t.Helper()
	store := keystore.NewMemory()
	if _, err := store.Create(context.Background(), "agent-1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc, err := capability.NewService(store, capability.Options{
		Clock:  func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, capabilityhttp.Handler(svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func do(t *testing.T, h http.Handler, method, path string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	if rec.Body.Len() > 0 && rec.Header().Get("Content-Type") == "application/json" {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("unmarshal response: %v\nbody: %s", err, rec.Body.String())
		}
	}
	return rec, out
}

func TestIssueHandlerHappyPath(t *testing.T) {
	_, h := newServer(t, time.Unix(1_700_000_000, 0))
	rec, out := do(t, h, "POST", "/v1/tokens", map[string]any{
		"agent_id":     "agent-1",
		"action_types": []string{"transfer"},
		"targets":      []string{"acct:1"},
		"ttl_seconds":  3600,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status: got %d want 201, body: %s", rec.Code, rec.Body.String())
	}
	for _, k := range []string{"token_id", "claims_json", "signature_hex"} {
		if _, ok := out[k]; !ok {
			t.Fatalf("missing field %q in response: %v", k, out)
		}
	}
}

func TestIssueHandlerErrors(t *testing.T) {
	_, h := newServer(t, time.Unix(1_700_000_000, 0))

	cases := []struct {
		name   string
		body   any
		status int
		code   string
	}{
		{"unparseable body", "not-json", http.StatusBadRequest, "invalid_json"},
		{"missing agent_id", map[string]any{"action_types": []string{"x"}, "targets": []string{"y"}, "ttl_seconds": 60}, http.StatusBadRequest, "missing_field"},
		{"missing action_types", map[string]any{"agent_id": "agent-1", "targets": []string{"y"}, "ttl_seconds": 60}, http.StatusBadRequest, "missing_field"},
		{"missing targets", map[string]any{"agent_id": "agent-1", "action_types": []string{"x"}, "ttl_seconds": 60}, http.StatusBadRequest, "missing_field"},
		{"invalid ttl", map[string]any{"agent_id": "agent-1", "action_types": []string{"x"}, "targets": []string{"y"}, "ttl_seconds": 0}, http.StatusBadRequest, "invalid_ttl"},
		{"unknown agent", map[string]any{"agent_id": "ghost", "action_types": []string{"x"}, "targets": []string{"y"}, "ttl_seconds": 60}, http.StatusNotFound, "unknown_agent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, out := do(t, h, "POST", "/v1/tokens", tc.body)
			if rec.Code != tc.status {
				t.Fatalf("status: got %d want %d", rec.Code, tc.status)
			}
			if out["error"] != tc.code {
				t.Fatalf("error: got %v want %q", out["error"], tc.code)
			}
		})
	}
}

func issueTok(t *testing.T, h http.Handler, agent string, types, targets []string, ttl int64) (string, string, string) {
	t.Helper()
	rec, out := do(t, h, "POST", "/v1/tokens", map[string]any{
		"agent_id":     agent,
		"action_types": types,
		"targets":      targets,
		"ttl_seconds":  ttl,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body.String())
	}
	return out["token_id"].(string), out["claims_json"].(string), out["signature_hex"].(string)
}

func TestVerifyHandlerHappyPath(t *testing.T) {
	_, h := newServer(t, time.Unix(1_700_000_000, 0))
	id, claims, sig := issueTok(t, h, "agent-1", []string{"transfer"}, []string{"acct:1"}, 3600)
	rec, out := do(t, h, "POST", "/v1/tokens/verify", map[string]any{
		"claims_json":   claims,
		"signature_hex": sig,
		"agent_id":      "agent-1",
		"action_type":   "transfer",
		"target":        "acct:1",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", rec.Code, rec.Body.String())
	}
	if out["ok"] != true || out["token_id"] != id {
		t.Fatalf("response: %v", out)
	}
}

func TestVerifyHandlerErrorsMapping(t *testing.T) {
	svc, h := newServer(t, time.Unix(1_700_000_000, 0))
	_, claims, sig := issueTok(t, h, "agent-1", []string{"transfer"}, []string{"acct:1"}, 3600)

	cases := []struct {
		name    string
		mutate  func(req map[string]any) // mutates a base verify request
		status  int
		errCode string
		// optional: change svc state before request
		setup func()
	}{
		{
			name:    "invalid_signature_hex",
			mutate:  func(r map[string]any) { r["signature_hex"] = "not-hex" },
			status:  http.StatusBadRequest,
			errCode: "invalid_signature_hex",
		},
		{
			name:    "missing_field",
			mutate:  func(r map[string]any) { delete(r, "agent_id") },
			status:  http.StatusBadRequest,
			errCode: "missing_field",
		},
		{
			name:    "malformed_token",
			mutate:  func(r map[string]any) { r["claims_json"] = "not-json" },
			status:  http.StatusBadRequest,
			errCode: "malformed_token",
		},
		{
			name:    "agent_mismatch",
			mutate:  func(r map[string]any) { r["agent_id"] = "other" },
			status:  http.StatusForbidden,
			errCode: "agent_mismatch",
		},
		{
			name:    "action_type_not_allowed",
			mutate:  func(r map[string]any) { r["action_type"] = "withdraw" },
			status:  http.StatusForbidden,
			errCode: "action_type_not_allowed",
		},
		{
			name:    "target_not_allowed",
			mutate:  func(r map[string]any) { r["target"] = "acct:other" },
			status:  http.StatusForbidden,
			errCode: "target_not_allowed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.setup != nil {
				tc.setup()
			}
			req := map[string]any{
				"claims_json":   claims,
				"signature_hex": sig,
				"agent_id":      "agent-1",
				"action_type":   "transfer",
				"target":        "acct:1",
			}
			tc.mutate(req)
			rec, out := do(t, h, "POST", "/v1/tokens/verify", req)
			if rec.Code != tc.status {
				t.Fatalf("status: got %d want %d", rec.Code, tc.status)
			}
			if out["error"] != tc.errCode {
				t.Fatalf("error: got %v want %q", out["error"], tc.errCode)
			}
		})
	}

	_ = svc
}

// Expired/revoked need clock control, so they get their own server with a
// mutable clock variable closed over.
func TestVerifyExpiredAndRevokedFlows(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	store := keystore.NewMemory()
	if _, err := store.Create(context.Background(), "agent-1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	clock := now
	svc, err := capability.NewService(store, capability.Options{
		Clock:  func() time.Time { return clock },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("svc: %v", err)
	}
	h := capabilityhttp.Handler(svc, slog.New(slog.NewTextHandler(io.Discard, nil)))

	id, claims, sig := issueTok(t, h, "agent-1", []string{"transfer"}, []string{"acct:1"}, 60)

	// revoked
	rec, _ := do(t, h, "POST", "/v1/tokens/"+id+"/revoke", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke status: %d", rec.Code)
	}
	rec, out := do(t, h, "POST", "/v1/tokens/verify", map[string]any{
		"claims_json": claims, "signature_hex": sig,
		"agent_id": "agent-1", "action_type": "transfer", "target": "acct:1",
	})
	if rec.Code != http.StatusForbidden || out["error"] != "revoked" {
		t.Fatalf("revoked path: %d %v", rec.Code, out)
	}

	// expired (use a fresh token, then advance clock)
	id2, claims2, sig2 := issueTok(t, h, "agent-1", []string{"transfer"}, []string{"acct:1"}, 60)
	_ = id2
	clock = time.Unix(now.Unix()+60, 0)
	rec, out = do(t, h, "POST", "/v1/tokens/verify", map[string]any{
		"claims_json": claims2, "signature_hex": sig2,
		"agent_id": "agent-1", "action_type": "transfer", "target": "acct:1",
	})
	if rec.Code != http.StatusForbidden || out["error"] != "expired" {
		t.Fatalf("expired path: %d %v", rec.Code, out)
	}
}

func TestRevokeIdempotent(t *testing.T) {
	_, h := newServer(t, time.Unix(1_700_000_000, 0))
	rec, _ := do(t, h, "POST", "/v1/tokens/never-issued/revoke", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke unknown: %d", rec.Code)
	}
}

func TestSigningPubkey(t *testing.T) {
	_, h := newServer(t, time.Unix(1_700_000_000, 0))
	rec, out := do(t, h, "GET", "/v1/tokens/signing-pubkey", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: %d", rec.Code)
	}
	v, _ := out["public_key_hex"].(string)
	if len(v) != 64 { // 32 bytes hex-encoded
		t.Fatalf("pubkey hex length: %d (%q)", len(v), v)
	}
}
