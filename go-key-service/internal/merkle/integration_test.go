package merkle

import (
	"crypto/rand"
	"strings"
	"testing"
)

// TestIntegrationTamperedLeafFlagged is the acceptance test for issue #12:
// build N=64 random leaves, snapshot the root at size=32, then tamper
// leaf #10 in place — the verifier must flag divergence with a clear
// hex-bearing diagnostic.
func TestIntegrationTamperedLeafFlagged(t *testing.T) {
	tr := New()
	for i := 0; i < 64; i++ {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		tr.Append(buf)
	}
	snapshot, err := tr.RootAt(32)
	if err != nil {
		t.Fatal(err)
	}

	// In-place tamper of leaf 10 (well inside the snapshot range).
	tr.mu.Lock()
	tr.leaves[10] = HashLeaf([]byte("attacker-substituted-action"))
	tr.mu.Unlock()

	v := NewVerifier(tr)
	report, err := v.VerifyHistoricalRoot(snapshot, 32)
	if err == nil {
		t.Fatalf("verifier failed to flag tampered leaf — report=%+v", report)
	}
	if report.OK {
		t.Fatal("report.OK must be false on tamper")
	}
	if report.LiveSize != 64 || report.HistoricalSize != 32 {
		t.Fatalf("sizes wrong: %+v", report)
	}
	for _, want := range []string{"root mismatch", "derived"} {
		if !strings.Contains(report.Message, want) {
			t.Fatalf("diagnostic missing %q: %q", want, report.Message)
		}
	}
}
