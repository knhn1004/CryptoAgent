package signing

import (
	"crypto/rand"
	"testing"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
)

func BenchmarkSign(b *testing.B) {
	_, priv, _ := GenerateKey(rand.Reader)
	a := &action.Action{
		SchemaVersion: 1,
		AgentID:       "agent-bench",
		ActionType:    "noop",
		Target:        "peer-bench",
		TimestampMs:   1700000000000,
		Nonce:         "0123456789abcdef0123456789abcdef",
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(a, priv); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	pub, priv, _ := GenerateKey(rand.Reader)
	a := &action.Action{
		SchemaVersion: 1,
		AgentID:       "agent-bench",
		ActionType:    "noop",
		Target:        "peer-bench",
		TimestampMs:   1700000000000,
		Nonce:         "0123456789abcdef0123456789abcdef",
	}
	sig, _ := Sign(a, priv)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(a, sig, pub); err != nil {
			b.Fatal(err)
		}
	}
}
