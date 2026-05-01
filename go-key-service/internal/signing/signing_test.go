package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
)

func sampleAction() *action.Action {
	return &action.Action{
		SchemaVersion: 1,
		AgentID:       "agent-001",
		ActionType:    "ping",
		Target:        "peer-002",
		TimestampMs:   1700000000000,
		Nonce:         "0123456789abcdef0123456789abcdef",
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := sampleAction()
	sig, err := Sign(a, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(a, sig, pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyWrongKeyRejected(t *testing.T) {
	_, priv, _ := GenerateKey(rand.Reader)
	otherPub, _, _ := GenerateKey(rand.Reader)
	a := sampleAction()
	sig, _ := Sign(a, priv)
	if err := Verify(a, sig, otherPub); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got %v want ErrInvalidSignature", err)
	}
}

func TestVerifyTamperedActionRejected(t *testing.T) {
	pub, priv, _ := GenerateKey(rand.Reader)
	a := sampleAction()
	sig, _ := Sign(a, priv)
	a.Target = "peer-evil"
	if err := Verify(a, sig, pub); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got %v want ErrInvalidSignature", err)
	}
}

func TestVerifyTamperedSignatureRejected(t *testing.T) {
	pub, priv, _ := GenerateKey(rand.Reader)
	a := sampleAction()
	sig, _ := Sign(a, priv)
	sig[0] ^= 0xFF
	if err := Verify(a, sig, pub); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("got %v want ErrInvalidSignature", err)
	}
}

func TestSignBadKeyLength(t *testing.T) {
	a := sampleAction()
	if _, err := Sign(a, ed25519.PrivateKey{1, 2, 3}); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("got %v want ErrInvalidKeyLength", err)
	}
}

func TestVerifyBadKeyLength(t *testing.T) {
	a := sampleAction()
	if err := Verify(a, []byte{}, ed25519.PublicKey{1}); !errors.Is(err, ErrInvalidKeyLength) {
		t.Fatalf("got %v want ErrInvalidKeyLength", err)
	}
}
