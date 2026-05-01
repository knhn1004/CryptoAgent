package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
)

type interopVector struct {
	Action       action.Action `json:"action"`
	CanonicalHex string        `json:"canonical_hex"`
	PublicKey    string        `json:"public_key"`
	Seed         string        `json:"seed"`
	SignatureHex string        `json:"signature_hex"`
}

func loadVector(t *testing.T) interopVector {
	t.Helper()
	_, here, _, _ := runtime.Caller(0)
	// here = .../go-key-service/internal/signing/interop_test.go
	// vectors at .../docs/signing_vectors.json
	root := filepath.Join(filepath.Dir(here), "..", "..", "..", "docs", "signing_vectors.json")
	raw, err := os.ReadFile(root)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v interopVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return v
}

func TestInteropFixedVector(t *testing.T) {
	v := loadVector(t)

	canonical, err := v.Action.Canonical()
	if err != nil {
		t.Fatalf("Canonical: %v", err)
	}
	wantCanonical, err := hex.DecodeString(v.CanonicalHex)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, wantCanonical) {
		t.Fatalf("canonical mismatch:\n got %q\nwant %q", canonical, wantCanonical)
	}

	seed, _ := hex.DecodeString(v.Seed)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	gotPub, _ := hex.DecodeString(v.PublicKey)
	if !bytes.Equal(pub, gotPub) {
		t.Fatalf("public key mismatch")
	}

	sig, err := Sign(&v.Action, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	wantSig, _ := hex.DecodeString(v.SignatureHex)
	if !bytes.Equal(sig, wantSig) {
		t.Fatalf("signature mismatch:\n got %x\nwant %x", sig, wantSig)
	}

	if err := Verify(&v.Action, wantSig, pub); err != nil {
		t.Fatalf("Verify fixed signature: %v", err)
	}
}
