// vector_gen produces docs/signing_vectors.json from a fixed seed.
// Run: go run ./internal/signing/vector_gen > ../docs/signing_vectors.json
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/signing"
)

func main() {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	a := &action.Action{
		SchemaVersion: 1,
		AgentID:       "agent-001",
		ActionType:    "ping",
		Target:        "peer-002",
		TimestampMs:   1700000000000,
		Nonce:         "0123456789abcdef0123456789abcdef",
	}
	canonical, err := a.Canonical()
	if err != nil {
		panic(err)
	}
	sig, err := signing.Sign(a, priv)
	if err != nil {
		panic(err)
	}

	out := map[string]any{
		"seed":           hex.EncodeToString(seed),
		"public_key":     hex.EncodeToString(pub),
		"action":         a,
		"canonical_hex":  hex.EncodeToString(canonical),
		"signature_hex":  hex.EncodeToString(sig),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
