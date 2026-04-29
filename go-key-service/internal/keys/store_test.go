package keys

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestMemoryStore_CreateGeneratesValidEd25519Key(t *testing.T) {
	s := NewMemoryStore()
	pub, err := s.Create("agent-001")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key size = %d, want %d", len(pub), ed25519.PublicKeySize)
	}
}

func TestMemoryStore_CreateProducesDistinctKeys(t *testing.T) {
	s := NewMemoryStore()
	pub1, err := s.Create("agent-001")
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := s.Create("agent-002")
	if err != nil {
		t.Fatal(err)
	}
	if string(pub1) == string(pub2) {
		t.Fatal("expected distinct keys for distinct agents")
	}
}

func TestMemoryStore_PublicKeyRoundTrip(t *testing.T) {
	s := NewMemoryStore()
	pub, err := s.Create("agent-001")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.PublicKey("agent-001")
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if string(got) != string(pub) {
		t.Fatal("PublicKey returned a different key than Create")
	}
}

func TestMemoryStore_PublicKeyMissing(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.PublicKey("nope")
	if !errors.Is(err, ErrAgentNotFound) {
		t.Fatalf("err = %v, want ErrAgentNotFound", err)
	}
}

func TestMemoryStore_CreateRejectsDuplicate(t *testing.T) {
	s := NewMemoryStore()
	if _, err := s.Create("agent-001"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Create("agent-001")
	if !errors.Is(err, ErrAgentExists) {
		t.Fatalf("second Create err = %v, want ErrAgentExists", err)
	}
}

func TestMemoryStore_CreateRejectsDuplicateLeavesKeyIntact(t *testing.T) {
	// A rejected re-registration must not overwrite the existing keypair.
	s := NewMemoryStore()
	pub, err := s.Create("agent-001")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = s.Create("agent-001")
	got, err := s.PublicKey("agent-001")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(pub) {
		t.Fatal("re-registration mutated stored key")
	}
}

func TestMemoryStore_CreateRejectsEmptyID(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.Create("")
	if !errors.Is(err, ErrEmptyAgentID) {
		t.Fatalf("err = %v, want ErrEmptyAgentID", err)
	}
}

func TestMemoryStore_KeyIsSignable(t *testing.T) {
	// Ensures the keypair we return actually sign/verifies — i.e. we stored
	// the matching private key, not garbage.
	s := NewMemoryStore()
	pub, err := s.Create("agent-001")
	if err != nil {
		t.Fatal(err)
	}
	priv := s.keys["agent-001"]
	msg := []byte("hello")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("returned public key does not verify signature from stored private key")
	}
}
