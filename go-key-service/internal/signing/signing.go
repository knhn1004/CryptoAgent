// Package signing produces Ed25519 signatures over canonical action bytes.
// The Go and Python implementations MUST agree byte-for-byte; see
// docs/schema.md and docs/signing_vectors.json.
package signing

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
)

var (
	ErrInvalidSignature = errors.New("signing: invalid signature")
	ErrInvalidKeyLength = errors.New("signing: invalid key length")
)

// Sign canonicalizes the action and returns its Ed25519 signature.
func Sign(a *action.Action, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: private key %d bytes", ErrInvalidKeyLength, len(priv))
	}
	msg, err := a.Canonical()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(priv, msg), nil
}

// Verify returns nil iff sig is a valid Ed25519 signature on the canonical
// bytes of a under pub.
func Verify(a *action.Action, sig []byte, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: public key %d bytes", ErrInvalidKeyLength, len(pub))
	}
	msg, err := a.Canonical()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// GenerateKey wraps ed25519.GenerateKey so callers don't need to import
// crypto/ed25519 directly.
func GenerateKey(rand io.Reader) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand)
}
