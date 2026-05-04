package capability

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keystore"
)

func newTestService(t *testing.T, now time.Time) (*Service, keystore.KeyStore) {
	t.Helper()
	store := keystore.NewMemory()
	if _, err := store.Create(context.Background(), "agent-1"); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	clock := func() time.Time { return now }
	svc, err := NewService(store, Options{
		Clock:  clock,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}

func issueTestToken(t *testing.T, svc *Service, agent string, types, targets []string, ttl int64) (*Token, []byte, []byte) {
	t.Helper()
	tok, claims, sig, err := svc.Issue(context.Background(), IssueRequest{
		AgentID:     agent,
		ActionTypes: types,
		Targets:     targets,
		TTLSeconds:  ttl,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok, claims, sig
}

func TestIssueHappyPath(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	svc, _ := newTestService(t, now)
	tok, claims, sig := issueTestToken(t, svc, "agent-1", []string{"transfer"}, []string{"acct:1"}, 3600)

	if tok.TokenID == "" {
		t.Fatalf("token_id is empty")
	}
	if tok.IssuedAt != now.Unix() {
		t.Fatalf("issued_at: got %d want %d", tok.IssuedAt, now.Unix())
	}
	if tok.ExpiresAt != now.Unix()+3600 {
		t.Fatalf("expires_at: got %d want %d", tok.ExpiresAt, now.Unix()+3600)
	}
	if !ed25519.Verify(svc.SigningPublicKey(), claims, sig) {
		t.Fatalf("signature does not verify")
	}
}

func TestIssueRejectsUnknownAgent(t *testing.T) {
	svc, _ := newTestService(t, time.Unix(1_700_000_000, 0))
	_, _, _, err := svc.Issue(context.Background(), IssueRequest{
		AgentID:     "ghost",
		ActionTypes: []string{"x"},
		Targets:     []string{"y"},
		TTLSeconds:  60,
	})
	if !errors.Is(err, ErrUnknownAgent) {
		t.Fatalf("got %v want ErrUnknownAgent", err)
	}
}

func TestIssueRejectsInvalidTTL(t *testing.T) {
	svc, _ := newTestService(t, time.Unix(1_700_000_000, 0))
	for _, ttl := range []int64{0, -1} {
		_, _, _, err := svc.Issue(context.Background(), IssueRequest{
			AgentID:     "agent-1",
			ActionTypes: []string{"x"},
			Targets:     []string{"y"},
			TTLSeconds:  ttl,
		})
		if !errors.Is(err, ErrInvalidTTL) {
			t.Fatalf("ttl=%d: got %v want ErrInvalidTTL", ttl, err)
		}
	}
}

func TestIssueGeneratesUniqueTokenIDs(t *testing.T) {
	svc, _ := newTestService(t, time.Unix(1_700_000_000, 0))
	a, _, _ := issueTestToken(t, svc, "agent-1", []string{"x"}, []string{"y"}, 60)
	b, _, _ := issueTestToken(t, svc, "agent-1", []string{"x"}, []string{"y"}, 60)
	if a.TokenID == b.TokenID {
		t.Fatalf("expected unique token_ids, both = %q", a.TokenID)
	}
}

func TestCanonicalSortsListsAndKeys(t *testing.T) {
	tok := &Token{
		TokenID:     "id",
		AgentID:     "a",
		ActionTypes: []string{"z", "a", "m"},
		Targets:     []string{"t2", "t1"},
		IssuedAt:    1,
		ExpiresAt:   2,
	}
	got, err := tok.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	want := `{"action_types":["a","m","z"],"agent_id":"a","expires_at":2,"issued_at":1,"targets":["t1","t2"],"token_id":"id"}`
	if string(got) != want {
		t.Fatalf("canonical mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestVerifyHappyPath(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	svc, _ := newTestService(t, now)
	_, claims, sig := issueTestToken(t, svc, "agent-1", []string{"transfer"}, []string{"acct:1"}, 3600)

	tok, err := svc.Verify(context.Background(), VerifyRequest{
		ClaimsJSON: claims,
		Signature:  sig,
		AgentID:    "agent-1",
		ActionType: "transfer",
		Target:     "acct:1",
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if tok == nil || tok.AgentID != "agent-1" {
		t.Fatalf("unexpected token: %+v", tok)
	}
}

func TestVerifyExpiredAtBoundary(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	svc, _ := newTestService(t, now)
	tok, claims, sig := issueTestToken(t, svc, "agent-1", []string{"x"}, []string{"y"}, 60)

	// Tick clock forward to exactly expires_at — should be expired.
	svc.clock = func() time.Time { return time.Unix(tok.ExpiresAt, 0) }
	_, err := svc.Verify(context.Background(), VerifyRequest{
		ClaimsJSON: claims, Signature: sig,
		AgentID: "agent-1", ActionType: "x", Target: "y",
	})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("at boundary: got %v want ErrExpired", err)
	}
}

func TestVerifyRevoked(t *testing.T) {
	svc, _ := newTestService(t, time.Unix(1_700_000_000, 0))
	tok, claims, sig := issueTestToken(t, svc, "agent-1", []string{"x"}, []string{"y"}, 600)
	svc.Revoke(context.Background(), tok.TokenID)
	_, err := svc.Verify(context.Background(), VerifyRequest{
		ClaimsJSON: claims, Signature: sig,
		AgentID: "agent-1", ActionType: "x", Target: "y",
	})
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v want ErrRevoked", err)
	}
	// Re-revoke is idempotent.
	svc.Revoke(context.Background(), tok.TokenID)
}

func TestVerifyAgentMismatch(t *testing.T) {
	svc, store := newTestService(t, time.Unix(1_700_000_000, 0))
	if _, err := store.Create(context.Background(), "agent-2"); err != nil {
		t.Fatalf("seed agent-2: %v", err)
	}
	_, claims, sig := issueTestToken(t, svc, "agent-1", []string{"x"}, []string{"y"}, 600)
	_, err := svc.Verify(context.Background(), VerifyRequest{
		ClaimsJSON: claims, Signature: sig,
		AgentID: "agent-2", ActionType: "x", Target: "y",
	})
	if !errors.Is(err, ErrAgentMismatch) {
		t.Fatalf("got %v want ErrAgentMismatch", err)
	}
}

func TestVerifyActionTypeNotAllowed(t *testing.T) {
	svc, _ := newTestService(t, time.Unix(1_700_000_000, 0))
	_, claims, sig := issueTestToken(t, svc, "agent-1", []string{"transfer"}, []string{"y"}, 600)
	_, err := svc.Verify(context.Background(), VerifyRequest{
		ClaimsJSON: claims, Signature: sig,
		AgentID: "agent-1", ActionType: "withdraw", Target: "y",
	})
	if !errors.Is(err, ErrActionTypeNotAllowed) {
		t.Fatalf("got %v want ErrActionTypeNotAllowed", err)
	}
}

func TestVerifyTargetNotAllowed(t *testing.T) {
	svc, _ := newTestService(t, time.Unix(1_700_000_000, 0))
	_, claims, sig := issueTestToken(t, svc, "agent-1", []string{"transfer"}, []string{"acct:1"}, 600)
	_, err := svc.Verify(context.Background(), VerifyRequest{
		ClaimsJSON: claims, Signature: sig,
		AgentID: "agent-1", ActionType: "transfer", Target: "acct:2",
	})
	if !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("got %v want ErrTargetNotAllowed", err)
	}
}

func TestVerifyWildcards(t *testing.T) {
	svc, _ := newTestService(t, time.Unix(1_700_000_000, 0))
	_, claims, sig := issueTestToken(t, svc, "agent-1", []string{"*"}, []string{"*"}, 600)
	_, err := svc.Verify(context.Background(), VerifyRequest{
		ClaimsJSON: claims, Signature: sig,
		AgentID: "agent-1", ActionType: "anything", Target: "whatever",
	})
	if err != nil {
		t.Fatalf("wildcards should match: %v", err)
	}
}

func TestVerifyTamperedSignature(t *testing.T) {
	svc, _ := newTestService(t, time.Unix(1_700_000_000, 0))
	_, claims, sig := issueTestToken(t, svc, "agent-1", []string{"x"}, []string{"y"}, 600)
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0x01
	_, err := svc.Verify(context.Background(), VerifyRequest{
		ClaimsJSON: claims, Signature: tampered,
		AgentID: "agent-1", ActionType: "x", Target: "y",
	})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got %v want ErrInvalidSignature", err)
	}
}

func TestVerifyTamperedClaims(t *testing.T) {
	svc, _ := newTestService(t, time.Unix(1_700_000_000, 0))
	_, claims, sig := issueTestToken(t, svc, "agent-1", []string{"x"}, []string{"y"}, 600)
	// Modify a field after signing — signature must no longer verify.
	var m map[string]any
	if err := json.Unmarshal(claims, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["agent_id"] = "agent-evil"
	tampered, _ := json.Marshal(m)
	_, err := svc.Verify(context.Background(), VerifyRequest{
		ClaimsJSON: tampered, Signature: sig,
		AgentID: "agent-evil", ActionType: "x", Target: "y",
	})
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got %v want ErrInvalidSignature", err)
	}
}

func TestVerifyMalformedClaims(t *testing.T) {
	svc, _ := newTestService(t, time.Unix(1_700_000_000, 0))
	_, err := svc.Verify(context.Background(), VerifyRequest{
		ClaimsJSON: []byte("not-json"),
		Signature:  make([]byte, ed25519.SignatureSize),
		AgentID:    "agent-1", ActionType: "x", Target: "y",
	})
	if !errors.Is(err, ErrMalformedToken) {
		t.Fatalf("got %v want ErrMalformedToken", err)
	}
}
