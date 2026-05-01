package keystore

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryCreateAndGet(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	pub, err := m.Create(ctx, "agent-001")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(pub) != 32 {
		t.Fatalf("public key length: got %d want 32", len(pub))
	}

	gotPub, gotPriv, err := m.Get(ctx, "agent-001")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(gotPub) != string(pub) {
		t.Fatal("Get returned a different public key than Create")
	}
	if len(gotPriv) != 64 {
		t.Fatalf("private key length: got %d want 64", len(gotPriv))
	}
}

func TestMemoryDuplicateRejected(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if _, err := m.Create(ctx, "dup"); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	_, err := m.Create(ctx, "dup")
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("second Create: got %v want ErrAlreadyExists", err)
	}
}

func TestMemoryGetMissing(t *testing.T) {
	m := NewMemory()
	_, _, err := m.Get(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v want ErrNotFound", err)
	}
}

func TestMemoryList(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	for _, id := range []string{"b", "a", "c"} {
		if _, err := m.Create(ctx, id); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	ids, err := m.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(ids) != 3 || ids[0] != "a" || ids[1] != "b" || ids[2] != "c" {
		t.Fatalf("List sorted: got %v", ids)
	}
}

func TestMemoryDelete(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if _, err := m.Create(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(ctx, "x"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := m.Delete(ctx, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete: got %v want ErrNotFound", err)
	}
	if _, _, err := m.Get(ctx, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: got %v want ErrNotFound", err)
	}
}

func TestMemoryEmptyAgentIDRejected(t *testing.T) {
	m := NewMemory()
	if _, err := m.Create(context.Background(), ""); err == nil {
		t.Fatal("Create with empty id should fail")
	}
}
