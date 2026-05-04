package anchor

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"
)

// fakeTree is a TreeView whose size and root are caller-controlled so
// the committer can be exercised without spinning up a real RFC 6962
// tree.
type fakeTree struct {
	size uint64
	root []byte
}

func (f *fakeTree) Snapshot() (uint64, []byte) { return f.size, f.root }

func newRoot(b byte) []byte {
	out := make([]byte, HashSize)
	for i := range out {
		out[i] = b
	}
	return out
}

func newCommitter(t *testing.T, tree TreeView, client EVMClient) (*Committer, *LatestStore) {
	t.Helper()
	store := NewLatestStore()
	c, err := NewCommitter(tree, client, store, CommitterOptions{
		Interval: time.Hour, // we drive ticks via CommitOnce in tests
		Clock:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		Logger:   slog.New(slog.NewTextHandler(new(bytes.Buffer), nil)),
	})
	if err != nil {
		t.Fatalf("NewCommitter: %v", err)
	}
	return c, store
}

func TestCommitOnce_SuccessUpdatesStore(t *testing.T) {
	tree := &fakeTree{size: 5, root: newRoot(0xab)}
	client := NewFakeEVMClient()
	c, store := newCommitter(t, tree, client)

	a, ok, err := c.CommitOnce(context.Background())
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !ok {
		t.Fatalf("expected committed=true")
	}
	if a.TreeSize != 5 {
		t.Errorf("tree size: got %d want 5", a.TreeSize)
	}
	if !bytes.Equal(a.Root, tree.root) {
		t.Errorf("root mismatch: got %x want %x", a.Root, tree.root)
	}
	got, err := store.Latest()
	if err != nil {
		t.Fatalf("store.Latest: %v", err)
	}
	if got.TreeSize != 5 {
		t.Errorf("store size: got %d want 5", got.TreeSize)
	}
	if c.LastCommittedSize() != 5 {
		t.Errorf("LastCommittedSize: got %d want 5", c.LastCommittedSize())
	}
	if got := client.Calls(); got != 1 {
		t.Errorf("client calls: got %d want 1", got)
	}
}

func TestCommitOnce_SkipsWhenTreeUnchanged(t *testing.T) {
	tree := &fakeTree{size: 5, root: newRoot(0xab)}
	client := NewFakeEVMClient()
	c, _ := newCommitter(t, tree, client)

	if _, _, err := c.CommitOnce(context.Background()); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	// Second tick with same size — must not broadcast.
	_, ok, err := c.CommitOnce(context.Background())
	if !errors.Is(err, ErrTreeShrank) {
		t.Errorf("expected ErrTreeShrank, got %v", err)
	}
	if ok {
		t.Errorf("ok must be false on skip")
	}
	if got := client.Calls(); got != 1 {
		t.Errorf("client calls: got %d want 1", got)
	}
}

func TestCommitOnce_RejectsEmptyTree(t *testing.T) {
	tree := &fakeTree{size: 0, root: newRoot(0)}
	client := NewFakeEVMClient()
	c, _ := newCommitter(t, tree, client)

	_, ok, err := c.CommitOnce(context.Background())
	if !errors.Is(err, ErrEmptyTree) {
		t.Errorf("expected ErrEmptyTree, got %v", err)
	}
	if ok {
		t.Errorf("ok must be false on empty")
	}
	if got := client.Calls(); got != 0 {
		t.Errorf("client must not be called on empty tree, got %d", got)
	}
}

func TestCommitOnce_PropagatesClientError(t *testing.T) {
	tree := &fakeTree{size: 5, root: newRoot(0xab)}
	client := NewFakeEVMClient()
	want := errors.New("rpc down")
	client.SetNextError(want)

	c, store := newCommitter(t, tree, client)
	_, ok, err := c.CommitOnce(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrCommitFailed) {
		t.Errorf("error should wrap ErrCommitFailed: %v", err)
	}
	if ok {
		t.Error("ok must be false on rpc error")
	}
	if c.LastCommittedSize() != 0 {
		t.Errorf("LastCommittedSize must stay at 0 on failure, got %d", c.LastCommittedSize())
	}
	if _, err := store.Latest(); !errors.Is(err, ErrNoAnchorYet) {
		t.Errorf("store should be empty on failure, got %v", err)
	}
}

func TestCommitOnce_GrowingTreeProducesNewAnchors(t *testing.T) {
	tree := &fakeTree{size: 5, root: newRoot(0x01)}
	client := NewFakeEVMClient()
	c, store := newCommitter(t, tree, client)

	if _, _, err := c.CommitOnce(context.Background()); err != nil {
		t.Fatalf("first: %v", err)
	}
	tree.size = 9
	tree.root = newRoot(0x02)
	if _, _, err := c.CommitOnce(context.Background()); err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := client.Calls(); got != 2 {
		t.Errorf("expected 2 commits, got %d", got)
	}
	last, err := store.Latest()
	if err != nil {
		t.Fatalf("store.Latest: %v", err)
	}
	if last.TreeSize != 9 {
		t.Errorf("latest size: got %d want 9", last.TreeSize)
	}
	if !bytes.Equal(last.Root, tree.root) {
		t.Errorf("latest root mismatch")
	}
}

func TestNewCommitter_RequiresDeps(t *testing.T) {
	cases := []struct {
		name   string
		tree   TreeView
		client EVMClient
		store  *LatestStore
	}{
		{"no tree", nil, NewFakeEVMClient(), NewLatestStore()},
		{"no client", &fakeTree{}, nil, NewLatestStore()},
		{"no store", &fakeTree{}, NewFakeEVMClient(), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewCommitter(tc.tree, tc.client, tc.store, CommitterOptions{}); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestStartStopGracefully(t *testing.T) {
	tree := &fakeTree{size: 1, root: newRoot(0xa)}
	client := NewFakeEVMClient()
	store := NewLatestStore()
	c, err := NewCommitter(tree, client, store, CommitterOptions{
		Interval: 5 * time.Millisecond,
		Clock:    func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		Logger:   slog.New(slog.NewTextHandler(new(bytes.Buffer), nil)),
	})
	if err != nil {
		t.Fatalf("NewCommitter: %v", err)
	}
	c.Start(context.Background())
	// Give the loop a couple of ticks to do its first commit.
	time.Sleep(20 * time.Millisecond)
	if !c.Stop(time.Second) {
		t.Fatal("Stop did not exit cleanly")
	}
	if c.LastCommittedSize() == 0 {
		t.Errorf("expected at least one commit")
	}
}
