package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestEmptyRoot(t *testing.T) {
	tr := New()
	want := sha256.Sum256(nil)
	if !bytes.Equal(tr.Root(), want[:]) {
		t.Fatalf("empty root mismatch")
	}
}

func TestSingleLeafRoot(t *testing.T) {
	tr := New()
	tr.Append([]byte("a"))
	want := HashLeaf([]byte("a"))
	if !bytes.Equal(tr.Root(), want) {
		t.Fatalf("single-leaf root mismatch")
	}
}

func TestTwoLeafRoot(t *testing.T) {
	tr := New()
	tr.Append([]byte("a"))
	tr.Append([]byte("b"))
	want := HashChildren(HashLeaf([]byte("a")), HashLeaf([]byte("b")))
	if !bytes.Equal(tr.Root(), want) {
		t.Fatalf("two-leaf root mismatch")
	}
}

func TestThreeLeafRoot(t *testing.T) {
	tr := New()
	for _, s := range []string{"a", "b", "c"} {
		tr.Append([]byte(s))
	}
	want := HashChildren(
		HashChildren(HashLeaf([]byte("a")), HashLeaf([]byte("b"))),
		HashLeaf([]byte("c")),
	)
	if !bytes.Equal(tr.Root(), want) {
		t.Fatalf("three-leaf root mismatch")
	}
}

func TestEightLeafRoot(t *testing.T) {
	tr := New()
	for i := 0; i < 8; i++ {
		tr.Append([]byte(fmt.Sprintf("L%d", i)))
	}
	// Recompute expected.
	leaf := func(i int) []byte { return HashLeaf([]byte(fmt.Sprintf("L%d", i))) }
	left := HashChildren(
		HashChildren(leaf(0), leaf(1)),
		HashChildren(leaf(2), leaf(3)),
	)
	right := HashChildren(
		HashChildren(leaf(4), leaf(5)),
		HashChildren(leaf(6), leaf(7)),
	)
	want := HashChildren(left, right)
	if !bytes.Equal(tr.Root(), want) {
		t.Fatalf("8-leaf root mismatch:\n got %s\nwant %s",
			hex.EncodeToString(tr.Root()), hex.EncodeToString(want))
	}
}

func TestRootAt(t *testing.T) {
	tr := New()
	for i := 0; i < 5; i++ {
		tr.Append([]byte{byte(i)})
	}
	r3, err := tr.RootAt(3)
	if err != nil {
		t.Fatal(err)
	}
	tr2 := New()
	for i := 0; i < 3; i++ {
		tr2.Append([]byte{byte(i)})
	}
	if !bytes.Equal(r3, tr2.Root()) {
		t.Fatal("RootAt(3) != independent 3-leaf root")
	}
}

func TestRootAtOutOfRange(t *testing.T) {
	tr := New()
	tr.Append([]byte("a"))
	if _, err := tr.RootAt(99); err == nil {
		t.Fatal("expected error for out-of-range size")
	}
}
