package merkle

import (
	"errors"
	"strings"
	"testing"
)

func TestVerifierConsistentSnapshot(t *testing.T) {
	tr := buildTree(16)
	historical, err := tr.RootAt(7)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(tr)
	report, err := v.VerifyHistoricalRoot(historical, 7)
	if err != nil {
		t.Fatalf("verify err: %v", err)
	}
	if !report.OK {
		t.Fatalf("expected OK report, got %+v", report)
	}
}

func TestVerifierSizeRegression(t *testing.T) {
	tr := buildTree(4)
	v := NewVerifier(tr)
	report, err := v.VerifyHistoricalRoot(tr.Root(), 999)
	if !errors.Is(err, ErrSizeRegression) {
		t.Fatalf("expected size regression, got %v", err)
	}
	if report.OK {
		t.Fatal("report should not be OK")
	}
	if !strings.Contains(report.Message, "size regression") {
		t.Fatalf("diagnostic missing 'size regression': %q", report.Message)
	}
}

func TestVerifierWrongHistoricalRoot(t *testing.T) {
	tr := buildTree(8)
	v := NewVerifier(tr)
	wrong := append([]byte(nil), tr.Root()...)
	wrong[0] ^= 0xFF
	report, err := v.VerifyHistoricalRoot(wrong, 4)
	if err == nil {
		t.Fatal("expected error")
	}
	if report.OK {
		t.Fatal("report should not be OK")
	}
	if !strings.Contains(report.Message, "root mismatch") {
		t.Fatalf("diagnostic missing 'root mismatch': %q", report.Message)
	}
}

func TestVerifierTamperedLeafFlagged(t *testing.T) {
	tr := buildTree(32)
	historical, _ := tr.RootAt(16)

	tr.mu.Lock()
	tr.leaves[10] = HashLeaf([]byte("EVIL"))
	tr.mu.Unlock()

	v := NewVerifier(tr)
	report, err := v.VerifyHistoricalRoot(historical, 16)
	if err == nil {
		t.Fatal("expected divergence error")
	}
	if report.OK {
		t.Fatal("report should not be OK")
	}
	if !strings.Contains(report.Message, "root mismatch") {
		t.Fatalf("expected root-mismatch diagnostic, got %q", report.Message)
	}
}
