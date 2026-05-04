// Package anchor periodically commits the Merkle audit-log head to an
// on-chain witness contract (contracts/src/AuditAnchor.sol).
//
// Two pieces live here. The first is a small abstract EVMClient
// interface that the broadcaster speaks; the production binary wires
// it to a foundry `cast send` shell-out (see CastClient) so we do not
// pull go-ethereum into go.mod. The second is the Committer, a
// goroutine that polls a TreeView every Interval and submits a new
// (size, root, ts) tuple iff the tree has grown since the last
// successful commit. The contract enforces the same monotonicity
// constraint, so a duplicate commit on retry just reverts harmlessly.
//
// The Indexer is the read side: it stores the most recent commit in
// memory so the dashboard can read it via GET /v1/anchor/latest
// without a fresh RPC round-trip.
package anchor

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// HashSize is the length, in bytes, of the Merkle root we anchor.
// Mirrors merkle.HashSize; redeclared here so this package has no
// hard dependency on merkle.
const HashSize = 32

// Anchor is one (size, root) tuple committed on chain. The contract
// returns the same shape from `latest()` / `anchorAt(id)`.
type Anchor struct {
	ID          uint64    `json:"id"`
	TreeSize    uint64    `json:"tree_size"`
	Root        []byte    `json:"root"`
	Timestamp   time.Time `json:"timestamp"`
	BlockNumber uint64    `json:"block_number,omitempty"`
	TxHash      string    `json:"tx_hash,omitempty"`
}

// RootHex returns the 0x-prefixed hex string of the root, the form the
// contract expects in calldata and the indexer returns to the dashboard.
func (a Anchor) RootHex() string {
	return "0x" + hex.EncodeToString(a.Root)
}

// TreeView is the producer side: anything that can report the current
// (size, root) of the live Merkle tree. Implemented by *merkle.Tree
// directly (Size + Root); kept as an interface so tests can drive the
// committer with canned values.
type TreeView interface {
	Size() uint64
	Root() []byte
}

// EVMClient is the broadcaster contract. Real impls turn the call into
// an Ethereum transaction; the in-memory FakeEVMClient just records
// the calls for tests. Returning the on-chain id of the new anchor lets
// the committer correlate with `AuditAnchored(id, ...)` events later.
type EVMClient interface {
	// Commit submits (treeSize, root, ts) to AuditAnchor.commit. The
	// returned receipt carries the new anchor id and tx metadata when
	// the impl can produce them; a Noop/Cast impl may leave them zero.
	Commit(ctx context.Context, treeSize uint64, root []byte, ts time.Time) (CommitReceipt, error)
}

// CommitReceipt is the post-broadcast shape an EVMClient hands back.
type CommitReceipt struct {
	ID          uint64
	TxHash      string
	BlockNumber uint64
}

// Sentinel errors returned by Committer / EVMClient impls.
var (
	ErrTreeShrank   = errors.New("anchor: tree size did not grow since last commit")
	ErrInvalidRoot  = errors.New("anchor: root must be 32 bytes")
	ErrEmptyTree    = errors.New("anchor: tree is empty")
	ErrNoAnchorYet  = errors.New("anchor: no commit recorded yet")
	ErrCommitFailed = errors.New("anchor: commit failed")
)

// validateCommit centralises the basic sanity checks both the
// committer and the FakeEVMClient run before recording an anchor.
// Mirrors the contract's `EmptyTree` / `TreeShrank` reverts so unit
// tests can fail fast without a full chain round-trip.
func validateCommit(treeSize uint64, root []byte) error {
	if treeSize == 0 {
		return ErrEmptyTree
	}
	if len(root) != HashSize {
		return ErrInvalidRoot
	}
	return nil
}

// LatestStore is the read-side cache the indexer hands to the HTTP
// handler. The committer writes here on every successful broadcast;
// the handler reads via Latest().
type LatestStore struct {
	mu     sync.RWMutex
	latest *Anchor
}

func NewLatestStore() *LatestStore { return &LatestStore{} }

// Set replaces the cached anchor. Safe for concurrent use.
func (s *LatestStore) Set(a Anchor) {
	cp := a
	if a.Root != nil {
		cp.Root = append([]byte(nil), a.Root...)
	}
	s.mu.Lock()
	s.latest = &cp
	s.mu.Unlock()
}

// Latest returns the most recent anchor or ErrNoAnchorYet if the
// committer has not yet succeeded.
func (s *LatestStore) Latest() (Anchor, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.latest == nil {
		return Anchor{}, ErrNoAnchorYet
	}
	cp := *s.latest
	if s.latest.Root != nil {
		cp.Root = append([]byte(nil), s.latest.Root...)
	}
	return cp, nil
}

func formatErr(err error, treeSize uint64, root []byte) error {
	return fmt.Errorf("%w: size=%d root=%s: %v", ErrCommitFailed, treeSize, hex.EncodeToString(root), err)
}
