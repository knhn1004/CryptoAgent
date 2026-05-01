package merkle

import (
	"bytes"
	"fmt"
)

// ProofForRange returns the RFC 6962 consistency proof showing that the
// tree of size `oldSize` is a prefix of the tree of size `newSize`.
//
// 0 < oldSize <= newSize and newSize <= t.Size().
// For oldSize == 0 or oldSize == newSize, the proof is empty.
func (t *Tree) ProofForRange(oldSize, newSize uint64) ([][]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if newSize > uint64(len(t.leaves)) {
		return nil, fmt.Errorf("%w: newSize %d > current %d", ErrInvalidProof, newSize, len(t.leaves))
	}
	if oldSize > newSize {
		return nil, fmt.Errorf("%w: oldSize %d > newSize %d", ErrSizeRegression, oldSize, newSize)
	}
	if oldSize == 0 || oldSize == newSize {
		return nil, nil
	}
	return subproof(int(oldSize), t.leaves[:newSize], true), nil
}

// subproof corresponds to SUBPROOF(m, D[n], b) in RFC 6962 §2.1.2.
func subproof(m int, leaves [][]byte, atRoot bool) [][]byte {
	n := len(leaves)
	if m == n {
		if atRoot {
			return nil
		}
		return [][]byte{mth(leaves)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		out := subproof(m, leaves[:k], atRoot)
		out = append(out, mth(leaves[k:]))
		return out
	}
	out := subproof(m-k, leaves[k:], false)
	out = append(out, mth(leaves[:k]))
	return out
}

// VerifyConsistency implements the RFC 6962 §2.1.4.2 verification
// algorithm. Empty proof is valid iff oldSize == 0, oldSize == newSize, or
// oldSize == newSize and oldRoot == newRoot.
func VerifyConsistency(oldRoot, newRoot []byte, oldSize, newSize uint64, proof [][]byte) error {
	if oldSize > newSize {
		return fmt.Errorf("%w: oldSize %d > newSize %d", ErrSizeRegression, oldSize, newSize)
	}
	if oldSize == newSize {
		if !bytes.Equal(oldRoot, newRoot) {
			return fmt.Errorf("%w: equal sizes but different roots", ErrRootMismatch)
		}
		if len(proof) != 0 {
			return fmt.Errorf("%w: equal sizes require empty proof", ErrInvalidProof)
		}
		return nil
	}
	if oldSize == 0 {
		// Trivially consistent with any tree; proof must be empty.
		if len(proof) != 0 {
			return fmt.Errorf("%w: oldSize=0 requires empty proof", ErrInvalidProof)
		}
		return nil
	}

	// fn, sn track which subtrees we're combining.
	fn := oldSize - 1
	sn := newSize - 1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}

	// If oldSize is a power of two, the verifier prepends oldRoot to the proof.
	work := proof
	var fr, sr []byte
	if isPowerOfTwo(oldSize) {
		fr = append([]byte(nil), oldRoot...)
		sr = append([]byte(nil), oldRoot...)
	} else {
		if len(work) == 0 {
			return fmt.Errorf("%w: proof exhausted before consuming first node", ErrInvalidProof)
		}
		fr = append([]byte(nil), work[0]...)
		sr = append([]byte(nil), work[0]...)
		work = work[1:]
	}

	for sn > 0 {
		if len(work) == 0 {
			return fmt.Errorf("%w: proof exhausted at fn=%d sn=%d", ErrInvalidProof, fn, sn)
		}
		c := work[0]
		work = work[1:]
		if fn&1 == 1 || fn == sn {
			fr = HashChildren(c, fr)
			sr = HashChildren(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = HashChildren(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}

	if len(work) != 0 {
		return fmt.Errorf("%w: %d unused proof nodes", ErrInvalidProof, len(work))
	}
	if !bytes.Equal(fr, oldRoot) {
		return fmt.Errorf("%w: derived old root %x != %x", ErrRootMismatch, fr, oldRoot)
	}
	if !bytes.Equal(sr, newRoot) {
		return fmt.Errorf("%w: derived new root %x != %x", ErrRootMismatch, sr, newRoot)
	}
	return nil
}

func isPowerOfTwo(n uint64) bool {
	return n > 0 && n&(n-1) == 0
}
