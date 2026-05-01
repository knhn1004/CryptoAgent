package merkle

import (
	"errors"
	"fmt"
	"testing"
)

func buildTree(n int) *Tree {
	tr := New()
	for i := 0; i < n; i++ {
		tr.Append([]byte(fmt.Sprintf("leaf-%d", i)))
	}
	return tr
}

func TestConsistencyRoundTripAllPairs(t *testing.T) {
	const N = 10
	tr := buildTree(N)
	live := tr.Root()
	liveSize := tr.Size()

	for old := uint64(0); old <= liveSize; old++ {
		oldRoot, err := tr.RootAt(old)
		if err != nil {
			t.Fatalf("RootAt(%d): %v", old, err)
		}
		proof, err := tr.ProofForRange(old, liveSize)
		if err != nil {
			t.Fatalf("ProofForRange(%d,%d): %v", old, liveSize, err)
		}
		if err := VerifyConsistency(oldRoot, live, old, liveSize, proof); err != nil {
			t.Fatalf("VerifyConsistency(old=%d) failed: %v", old, err)
		}
	}
}

func TestConsistencyEqualSizesEqualRoots(t *testing.T) {
	tr := buildTree(4)
	r := tr.Root()
	if err := VerifyConsistency(r, r, 4, 4, nil); err != nil {
		t.Fatalf("equal-equal: %v", err)
	}
}

func TestConsistencySizeRegression(t *testing.T) {
	tr := buildTree(4)
	r := tr.Root()
	if err := VerifyConsistency(r, r, 5, 4, nil); !errors.Is(err, ErrSizeRegression) {
		t.Fatalf("expected size regression, got %v", err)
	}
}

func TestConsistencyTamperedProofRejected(t *testing.T) {
	tr := buildTree(8)
	live := tr.Root()
	oldRoot, _ := tr.RootAt(3)
	proof, _ := tr.ProofForRange(3, 8)
	// Flip a bit in the first proof element.
	proof[0] = append([]byte(nil), proof[0]...)
	proof[0][0] ^= 0xFF
	err := VerifyConsistency(oldRoot, live, 3, 8, proof)
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got %v", err)
	}
}

func TestConsistencyTruncatedProofRejected(t *testing.T) {
	tr := buildTree(8)
	live := tr.Root()
	oldRoot, _ := tr.RootAt(3)
	proof, _ := tr.ProofForRange(3, 8)
	if len(proof) > 0 {
		proof = proof[:len(proof)-1]
	}
	err := VerifyConsistency(oldRoot, live, 3, 8, proof)
	if !errors.Is(err, ErrInvalidProof) && !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("expected proof error, got %v", err)
	}
}

func TestConsistencyEqualSizesDifferentRoots(t *testing.T) {
	a := buildTree(3).Root()
	b := buildTree(4)
	other, _ := b.RootAt(3)
	other = append([]byte(nil), other...)
	other[0] ^= 1
	if err := VerifyConsistency(a, other, 3, 3, nil); !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("expected ErrRootMismatch, got %v", err)
	}
}

func TestConsistencyNonEmptyProofForEqualSizes(t *testing.T) {
	tr := buildTree(4)
	r := tr.Root()
	if err := VerifyConsistency(r, r, 4, 4, [][]byte{r}); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected ErrInvalidProof, got %v", err)
	}
}

func TestConsistencyZeroOldRequiresEmptyProof(t *testing.T) {
	tr := buildTree(4)
	r := tr.Root()
	if err := VerifyConsistency(nil, r, 0, 4, [][]byte{r}); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected ErrInvalidProof, got %v", err)
	}
}
