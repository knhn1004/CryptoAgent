package merkle

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"testing"
)

// TestPropertyAnyLeafMutationChangesRoot is the issue-#10 property test:
// for randomly sized trees and randomly chosen leaf indices, mutating
// that leaf in-place to a different value must always change the root.
func TestPropertyAnyLeafMutationChangesRoot(t *testing.T) {
	const iterations = 500
	rng := rand.New(rand.NewSource(0xC0FFEE))

	for it := 0; it < iterations; it++ {
		size := rng.Intn(64) + 1 // [1, 64]
		tr := New()
		original := make([][HashSize]byte, size)
		for i := 0; i < size; i++ {
			data := make([]byte, 16)
			rng.Read(data)
			h := sha256.Sum256(data)
			tr.AppendHashed(h[:])
			original[i] = h
		}
		rootBefore := tr.Root()

		// Pick a random leaf and mutate to a *different* hash.
		idx := rng.Intn(size)
		var replacement [HashSize]byte
		for {
			rng.Read(replacement[:])
			if replacement != original[idx] {
				break
			}
		}

		tr.mu.Lock()
		tr.leaves[idx] = append([]byte(nil), replacement[:]...)
		tr.mu.Unlock()

		rootAfter := tr.Root()
		if bytes.Equal(rootBefore, rootAfter) {
			t.Fatalf("iter=%d size=%d idx=%d: root unchanged after mutation", it, size, idx)
		}

		// Also confirm restoring the leaf returns the original root.
		tr.mu.Lock()
		tr.leaves[idx] = append([]byte(nil), original[idx][:]...)
		tr.mu.Unlock()
		if !bytes.Equal(rootBefore, tr.Root()) {
			t.Fatalf("iter=%d size=%d idx=%d: root did not restore after undo", it, size, idx)
		}
	}
}

// TestPropertyInclusionProofRejectsMutatedLeaf strengthens the property:
// not only does the root change, but the original inclusion proof for
// that leaf no longer verifies against the new root.
func TestPropertyInclusionProofRejectsMutatedLeaf(t *testing.T) {
	const iterations = 200
	rng := rand.New(rand.NewSource(0xBEEF))

	for it := 0; it < iterations; it++ {
		size := rng.Intn(32) + 2 // [2, 33]
		tr := New()
		data := make([][]byte, size)
		for i := 0; i < size; i++ {
			data[i] = []byte(fmt.Sprintf("seed-%d-%d", it, i))
			tr.Append(data[i])
		}
		idx := rng.Intn(size)
		proof, err := tr.Proof(uint64(idx))
		if err != nil {
			t.Fatal(err)
		}
		// Verify it works on the unchanged tree first.
		if err := VerifyInclusion(data[idx], uint64(idx), uint64(size), proof, tr.Root()); err != nil {
			t.Fatalf("baseline verify failed: %v", err)
		}
		// Mutate the leaf in place.
		newData := []byte(fmt.Sprintf("tampered-%d", it))
		tr.mu.Lock()
		tr.leaves[idx] = HashLeaf(newData)
		tr.mu.Unlock()
		// Old proof + old leaf data must no longer match the new root.
		if err := VerifyInclusion(data[idx], uint64(idx), uint64(size), proof, tr.Root()); err == nil {
			t.Fatalf("iter=%d size=%d idx=%d: stale proof verified against new root", it, size, idx)
		}
	}
}
