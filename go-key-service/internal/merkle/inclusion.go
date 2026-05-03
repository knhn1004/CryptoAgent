package merkle

import (
	"bytes"
	"fmt"
)

// Proof returns the RFC 6962 §2.1.1 inclusion (audit) proof for the leaf
// at idx. The returned slice is the bottom-up sequence of sibling node
// hashes needed to recompute the root from the leaf.
func (t *Tree) Proof(idx uint64) ([][]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := uint64(len(t.leaves))
	if n == 0 {
		return nil, fmt.Errorf("%w: empty tree", ErrInvalidProof)
	}
	if idx >= n {
		return nil, fmt.Errorf("%w: idx %d out of range [0,%d)", ErrInvalidProof, idx, n)
	}
	return path(int(idx), t.leaves), nil
}

// ProofAt returns the inclusion proof for leaf idx against the tree of
// size `size`. Useful when snapshotting historical roots.
func (t *Tree) ProofAt(idx, size uint64) ([][]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if size > uint64(len(t.leaves)) {
		return nil, fmt.Errorf("%w: size %d > current %d", ErrInvalidProof, size, len(t.leaves))
	}
	if size == 0 {
		return nil, fmt.Errorf("%w: empty tree", ErrInvalidProof)
	}
	if idx >= size {
		return nil, fmt.Errorf("%w: idx %d out of range [0,%d)", ErrInvalidProof, idx, size)
	}
	return path(int(idx), t.leaves[:size]), nil
}

// path corresponds to PATH(m, D[n]) in RFC 6962 §2.1.1.
func path(m int, leaves [][]byte) [][]byte {
	n := len(leaves)
	if n == 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(n)
	if m < k {
		return append(path(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(path(m-k, leaves[k:]), mth(leaves[:k]))
}

// VerifyInclusion checks that `leafData` is the leaf at index `idx` in a
// tree of `size` leaves whose head is `root`, given the inclusion proof
// produced by Tree.Proof. The leaf is hashed with the RFC 6962 leaf
// prefix internally; pass the same bytes that would be passed to Append.
func VerifyInclusion(leafData []byte, idx, size uint64, proof [][]byte, root []byte) error {
	return verifyInclusionFromHash(HashLeaf(leafData), idx, size, proof, root)
}

// VerifyInclusionHash is the prehashed variant of VerifyInclusion. The
// caller passes the leaf hash directly (i.e. HashLeaf(data)).
func VerifyInclusionHash(leafHash []byte, idx, size uint64, proof [][]byte, root []byte) error {
	if len(leafHash) != HashSize {
		return fmt.Errorf("%w: leaf hash must be %d bytes", ErrInvalidProof, HashSize)
	}
	return verifyInclusionFromHash(leafHash, idx, size, proof, root)
}

func verifyInclusionFromHash(leafHash []byte, idx, size uint64, proof [][]byte, root []byte) error {
	if size == 0 {
		return fmt.Errorf("%w: tree size 0", ErrInvalidProof)
	}
	if idx >= size {
		return fmt.Errorf("%w: idx %d >= size %d", ErrInvalidProof, idx, size)
	}
	if len(root) != HashSize {
		return fmt.Errorf("%w: root must be %d bytes", ErrInvalidProof, HashSize)
	}

	r := append([]byte(nil), leafHash...)
	fn := idx
	sn := size - 1

	for _, p := range proof {
		if len(p) != HashSize {
			return fmt.Errorf("%w: proof element wrong size", ErrInvalidProof)
		}
		if sn == 0 {
			return fmt.Errorf("%w: proof too long", ErrInvalidProof)
		}
		if fn&1 == 1 || fn == sn {
			r = HashChildren(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = HashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return fmt.Errorf("%w: proof too short", ErrInvalidProof)
	}
	if !bytes.Equal(r, root) {
		return fmt.Errorf("%w: derived %x != %x", ErrRootMismatch, r, root)
	}
	return nil
}
