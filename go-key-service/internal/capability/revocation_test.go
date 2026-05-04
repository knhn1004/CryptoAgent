package capability

import "testing"

func TestMemoryStoreRevokeAndQuery(t *testing.T) {
	s := NewMemoryStore()
	if s.IsRevoked("a") {
		t.Fatalf("fresh store reports revoked")
	}
	s.Revoke("a")
	if !s.IsRevoked("a") {
		t.Fatalf("Revoke did not stick")
	}
	// Idempotent.
	s.Revoke("a")
	if !s.IsRevoked("a") {
		t.Fatalf("second Revoke broke state")
	}
	if s.IsRevoked("b") {
		t.Fatalf("unrelated id reported revoked")
	}
}
