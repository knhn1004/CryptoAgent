package merkle

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenCreatesEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tree.log")

	tr, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	if tr.Size() != 0 {
		t.Fatalf("size: got %d want 0", tr.Size())
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file not created: %v", err)
	}
}

func TestOpenAppendCloseReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tree.log")

	tr, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	for _, d := range want {
		if _, err := tr.Append(d); err != nil {
			t.Fatal(err)
		}
	}
	rootBefore := tr.Root()
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}

	// File on disk should be exactly len(want) * HashSize bytes.
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, exp := stat.Size(), int64(len(want)*HashSize); got != exp {
		t.Fatalf("file size: got %d want %d", got, exp)
	}

	tr2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tr2.Close()

	if tr2.Size() != uint64(len(want)) {
		t.Fatalf("reopened size: got %d want %d", tr2.Size(), len(want))
	}
	if !bytes.Equal(tr2.Root(), rootBefore) {
		t.Fatal("root differs after reopen")
	}

	// Inclusion proof must still verify against the reopened tree.
	proof, err := tr2.Proof(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusion(want[2], 2, tr2.Size(), proof, tr2.Root()); err != nil {
		t.Fatalf("verify after reopen: %v", err)
	}
}

func TestOpenAppendsAcrossSessions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tree.log")

	tr, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := tr.Append([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	tr.Close()

	tr2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tr2.Close()
	for i := 3; i < 6; i++ {
		if _, err := tr2.Append([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}

	// Compare against an in-memory tree built from scratch.
	mem := New()
	for i := 0; i < 6; i++ {
		mem.Append([]byte{byte(i)})
	}
	if !bytes.Equal(tr2.Root(), mem.Root()) {
		t.Fatal("persisted root != in-memory root after multi-session append")
	}
}

func TestOpenRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.log")

	// Write a truncated record (not a multiple of HashSize).
	if err := os.WriteFile(path, []byte("not-32-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("expected error on file size not multiple of HashSize")
	}
}

func TestAppendAfterCloseFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tree.log")

	tr, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = tr.Append([]byte("x"))
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("want ErrClosed, got %v", err)
	}
}

func TestCloseInMemoryNoop(t *testing.T) {
	if err := New().Close(); err != nil {
		t.Fatalf("Close on in-memory tree: %v", err)
	}
}

func TestPersistedTreeMatchesInMemory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tree.log")

	tr, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	mem := New()
	for i := 0; i < 17; i++ {
		data := []byte(fmt.Sprintf("payload-%d", i))
		mem.Append(data)
		if _, err := tr.Append(data); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(tr.Root(), mem.Root()) {
		t.Fatal("persisted root != in-memory root")
	}
}
