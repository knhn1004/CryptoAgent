// Package merkle implements an RFC 6962-style append-only Merkle tree
// over agent-action leaves and the consistency-proof verification needed
// for the root-consistency job (issue #12).
//
// Hash domain separation matches RFC 6962:
//
//	leaf hash      = SHA-256(0x00 || data)
//	internal node  = SHA-256(0x01 || left || right)
package merkle

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
)

const (
	leafPrefix     byte = 0x00
	internalPrefix byte = 0x01
	HashSize            = sha256.Size
)

// Tree is an append-only Merkle tree. It stores hashed leaves; callers are
// responsible for choosing the leaf payload (per docs/schema.md, that is
// canonical(action) || signature).
type Tree struct {
	mu     sync.RWMutex
	leaves [][]byte // leaf hashes (already prefix-hashed via HashLeaf)
	file   *os.File // optional append-only backing file (set by Open)
	closed bool
}

func New() *Tree { return &Tree{} }

// HashLeaf computes the RFC 6962 leaf hash for arbitrary data.
func HashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	return h.Sum(nil)
}

// HashChildren computes the RFC 6962 internal-node hash.
func HashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{internalPrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// Append hashes data into a leaf, adds it, and (if backed by a file)
// flushes the leaf hash to disk before returning. Returns the new leaf
// index.
func (t *Tree) Append(data []byte) (uint64, error) {
	leafHash := HashLeaf(data)
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.persistLocked(leafHash); err != nil {
		return 0, err
	}
	t.leaves = append(t.leaves, leafHash)
	return uint64(len(t.leaves) - 1), nil
}

// AppendHashed adds an already-hashed leaf and persists it. Used by the
// verifier to reconstruct trees from external snapshots.
func (t *Tree) AppendHashed(leafHash []byte) (uint64, error) {
	if len(leafHash) != HashSize {
		return 0, fmt.Errorf("merkle: leaf hash must be %d bytes, got %d", HashSize, len(leafHash))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	cp := make([]byte, HashSize)
	copy(cp, leafHash)
	if err := t.persistLocked(cp); err != nil {
		return 0, err
	}
	t.leaves = append(t.leaves, cp)
	return uint64(len(t.leaves) - 1), nil
}

func (t *Tree) Size() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return uint64(len(t.leaves))
}

// Root returns the current Merkle tree head. Empty tree → SHA-256("").
func (t *Tree) Root() []byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return mth(t.leaves)
}

// Snapshot returns the current `(size, root)` pair under a single
// read lock, so callers (notably the on-chain anchor committer) get a
// consistent view even when appends are happening concurrently.
func (t *Tree) Snapshot() (uint64, []byte) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return uint64(len(t.leaves)), mth(t.leaves)
}

// RootAt returns the root of the tree's first `size` leaves.
func (t *Tree) RootAt(size uint64) ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if size > uint64(len(t.leaves)) {
		return nil, fmt.Errorf("%w: size %d > current %d", ErrInvalidProof, size, len(t.leaves))
	}
	return mth(t.leaves[:size]), nil
}

// LeafHashes returns a defensive copy of the underlying leaf hashes.
func (t *Tree) LeafHashes() [][]byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([][]byte, len(t.leaves))
	for i, h := range t.leaves {
		cp := make([]byte, len(h))
		copy(cp, h)
		out[i] = cp
	}
	return out
}

// mth = Merkle Tree Hash (RFC 6962 §2.1).
func mth(leaves [][]byte) []byte {
	n := len(leaves)
	if n == 0 {
		empty := sha256.Sum256(nil)
		return empty[:]
	}
	if n == 1 {
		out := make([]byte, HashSize)
		copy(out, leaves[0])
		return out
	}
	k := largestPowerOfTwoLessThan(n)
	return HashChildren(mth(leaves[:k]), mth(leaves[k:]))
}

// largestPowerOfTwoLessThan returns the largest power of two strictly less
// than n, for n >= 2.
func largestPowerOfTwoLessThan(n int) int {
	if n < 2 {
		panic("merkle: largestPowerOfTwoLessThan requires n >= 2")
	}
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// errors used across consistency / verifier.
var (
	ErrSizeRegression = errors.New("merkle: historical size larger than current size")
	ErrRootMismatch   = errors.New("merkle: root mismatch")
	ErrInvalidProof   = errors.New("merkle: invalid consistency proof")
)
