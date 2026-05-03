package merkle

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
)

func TestProofAndVerifyAllSizes(t *testing.T) {
	for size := 1; size <= 33; size++ {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			tr := New()
			leaves := make([][]byte, size)
			for i := 0; i < size; i++ {
				leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
				tr.Append(leaves[i])
			}
			root := tr.Root()
			for i := 0; i < size; i++ {
				proof, err := tr.Proof(uint64(i))
				if err != nil {
					t.Fatalf("Proof(%d): %v", i, err)
				}
				if err := VerifyInclusion(leaves[i], uint64(i), uint64(size), proof, root); err != nil {
					t.Fatalf("verify size=%d idx=%d: %v", size, i, err)
				}
			}
		})
	}
}

func TestProofKnownLayoutFourLeaves(t *testing.T) {
	tr := New()
	for _, s := range []string{"a", "b", "c", "d"} {
		tr.Append([]byte(s))
	}
	// Expected proof for idx=2: [HashLeaf(d), HashChildren(HashLeaf(a), HashLeaf(b))]
	want := [][]byte{
		HashLeaf([]byte("d")),
		HashChildren(HashLeaf([]byte("a")), HashLeaf([]byte("b"))),
	}
	got, err := tr.Proof(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("proof len: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("proof[%d] mismatch", i)
		}
	}
}

func TestProofOutOfRange(t *testing.T) {
	tr := New()
	tr.Append([]byte("a"))
	if _, err := tr.Proof(1); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("want ErrInvalidProof, got %v", err)
	}
}

func TestProofEmptyTree(t *testing.T) {
	tr := New()
	if _, err := tr.Proof(0); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("want ErrInvalidProof, got %v", err)
	}
}

func TestProofAt(t *testing.T) {
	tr := New()
	for i := 0; i < 8; i++ {
		tr.Append([]byte{byte(i)})
	}
	historicalRoot, err := tr.RootAt(5)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tr.ProofAt(2, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusion([]byte{2}, 2, 5, proof, historicalRoot); err != nil {
		t.Fatalf("ProofAt verify: %v", err)
	}
}

func TestVerifyInclusionTamperedLeaf(t *testing.T) {
	tr := New()
	for i := 0; i < 8; i++ {
		tr.Append([]byte{byte(i)})
	}
	proof, err := tr.Proof(3)
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInclusion([]byte("not-leaf-3"), 3, 8, proof, tr.Root())
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("want ErrRootMismatch, got %v", err)
	}
}

func TestVerifyInclusionTamperedProof(t *testing.T) {
	tr := New()
	for i := 0; i < 8; i++ {
		tr.Append([]byte{byte(i)})
	}
	proof, err := tr.Proof(3)
	if err != nil {
		t.Fatal(err)
	}
	proof[0][0] ^= 0xFF
	err = VerifyInclusion([]byte{3}, 3, 8, proof, tr.Root())
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("want ErrRootMismatch, got %v", err)
	}
}

func TestVerifyInclusionWrongRoot(t *testing.T) {
	tr := New()
	for i := 0; i < 4; i++ {
		tr.Append([]byte{byte(i)})
	}
	proof, _ := tr.Proof(1)
	wrongRoot := make([]byte, HashSize)
	if _, err := rand.Read(wrongRoot); err != nil {
		t.Fatal(err)
	}
	err := VerifyInclusion([]byte{1}, 1, 4, proof, wrongRoot)
	if !errors.Is(err, ErrRootMismatch) {
		t.Fatalf("want ErrRootMismatch, got %v", err)
	}
}

func TestVerifyInclusionTruncatedProofRejected(t *testing.T) {
	tr := New()
	for i := 0; i < 8; i++ {
		tr.Append([]byte{byte(i)})
	}
	proof, _ := tr.Proof(3)
	if err := VerifyInclusion([]byte{3}, 3, 8, proof[:len(proof)-1], tr.Root()); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyInclusionExtraProofRejected(t *testing.T) {
	tr := New()
	for i := 0; i < 8; i++ {
		tr.Append([]byte{byte(i)})
	}
	proof, _ := tr.Proof(3)
	extra := append(proof, make([]byte, HashSize))
	if err := VerifyInclusion([]byte{3}, 3, 8, extra, tr.Root()); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyInclusionIdxOutOfRange(t *testing.T) {
	tr := New()
	tr.Append([]byte("a"))
	err := VerifyInclusion([]byte("a"), 1, 1, nil, tr.Root())
	if !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("want ErrInvalidProof, got %v", err)
	}
}

func TestVerifyInclusionHashMatchesData(t *testing.T) {
	tr := New()
	for i := 0; i < 5; i++ {
		tr.Append([]byte{byte(i)})
	}
	proof, _ := tr.Proof(2)
	err := VerifyInclusionHash(HashLeaf([]byte{2}), 2, 5, proof, tr.Root())
	if err != nil {
		t.Fatalf("VerifyInclusionHash: %v", err)
	}
}
