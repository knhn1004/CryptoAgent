package merkle

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrClosed is returned by append operations on a Tree whose backing file
// has been closed.
var ErrClosed = errors.New("merkle: tree closed")

// Open returns a Tree backed by an append-only flat file at `path`. The
// file format is a concatenation of 32-byte leaf hashes; on open the file
// is read and the existing leaves are loaded into the in-memory tree.
//
// Subsequent calls to Append (and AppendHashed) flush the new leaf hash
// to disk and fsync before returning, so durability matches at-most-one
// leaf loss on crash.
//
// Callers must call Close when done. The zero value of Tree (returned by
// New) has no backing file and behaves as a pure in-memory tree.
func Open(path string) (*Tree, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("merkle: open %s: %w", path, err)
	}
	t := &Tree{file: f}
	if err := t.loadLocked(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return t, nil
}

// Close flushes and closes the backing file. Safe to call on an
// in-memory tree (no-op).
func (t *Tree) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.file == nil {
		return nil
	}
	err := t.file.Close()
	t.file = nil
	t.closed = true
	return err
}

// loadLocked reads all leaf hashes from t.file into t.leaves. Must be
// called with t.file at offset 0 (i.e., immediately after Open).
func (t *Tree) loadLocked() error {
	stat, err := t.file.Stat()
	if err != nil {
		return fmt.Errorf("merkle: stat: %w", err)
	}
	size := stat.Size()
	if size%int64(HashSize) != 0 {
		return fmt.Errorf("merkle: backing file size %d not a multiple of %d", size, HashSize)
	}
	n := int(size / int64(HashSize))
	if n == 0 {
		return nil
	}
	t.leaves = make([][]byte, n)
	buf := make([]byte, HashSize)
	for i := 0; i < n; i++ {
		if _, err := io.ReadFull(t.file, buf); err != nil {
			return fmt.Errorf("merkle: read leaf %d: %w", i, err)
		}
		cp := make([]byte, HashSize)
		copy(cp, buf)
		t.leaves[i] = cp
	}
	return nil
}

// persistLocked appends leafHash to the backing file (if any) and
// fsyncs. Must be called with t.mu held.
func (t *Tree) persistLocked(leafHash []byte) error {
	if t.closed {
		return ErrClosed
	}
	if t.file == nil {
		return nil
	}
	if _, err := t.file.Write(leafHash); err != nil {
		return fmt.Errorf("merkle: write leaf: %w", err)
	}
	if err := t.file.Sync(); err != nil {
		return fmt.Errorf("merkle: fsync: %w", err)
	}
	return nil
}
