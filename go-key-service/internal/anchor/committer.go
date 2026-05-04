package anchor

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

// Committer is the periodic poll-and-broadcast loop. Construct with
// NewCommitter, then Start; Stop blocks until the goroutine exits.
//
// On every tick the committer:
//
//  1. Reads (size, root) from the live tree.
//  2. Skips if size has not grown since the last successful commit.
//  3. Calls EVMClient.Commit. On success, updates LatestStore. On
//     failure, logs and retries on the next tick — no exponential
//     back-off, on the assumption that 15 min ticks already are the
//     back-off.
//
// The committer never blocks the audit-log append path; the tree is
// only ever read.
type Committer struct {
	tree     TreeView
	client   EVMClient
	store    *LatestStore
	interval time.Duration
	clock    func() time.Time
	logger   *slog.Logger

	lastCommitted atomic.Uint64

	stop chan struct{}
	done chan struct{}
}

// CommitterOptions configures a Committer; zero values get sensible
// defaults.
type CommitterOptions struct {
	// Interval between polls. Defaults to 15 minutes per issue #13.
	Interval time.Duration
	// Clock injected for tests. Defaults to time.Now.
	Clock func() time.Time
	// Logger injected for tests. Defaults to slog.Default.
	Logger *slog.Logger
}

// NewCommitter validates required deps and returns a stopped committer.
// Call Start to launch the goroutine.
func NewCommitter(tree TreeView, client EVMClient, store *LatestStore, opts CommitterOptions) (*Committer, error) {
	if tree == nil {
		return nil, errors.New("anchor: tree is required")
	}
	if client == nil {
		return nil, errors.New("anchor: evm client is required")
	}
	if store == nil {
		return nil, errors.New("anchor: latest store is required")
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	clock := opts.Clock
	if clock == nil {
		clock = time.Now
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Committer{
		tree:     tree,
		client:   client,
		store:    store,
		interval: interval,
		clock:    clock,
		logger:   logger,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}, nil
}

// Start launches the polling goroutine. Calling Start more than once
// panics — committers are not reusable.
func (c *Committer) Start(ctx context.Context) {
	go c.loop(ctx)
}

// Stop signals the loop to exit and waits up to `timeout` for the
// goroutine to drain. Returns true on clean exit.
func (c *Committer) Stop(timeout time.Duration) bool {
	close(c.stop)
	select {
	case <-c.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// CommitOnce runs one pass without waiting for the next tick. Used by
// the keyserver's `commit-now` admin endpoint and by tests that want a
// deterministic single shot.
func (c *Committer) CommitOnce(ctx context.Context) (Anchor, bool, error) {
	return c.commit(ctx)
}

// LastCommittedSize is the size of the most recent successful commit.
// 0 means we have not committed yet (or the tree is empty).
func (c *Committer) LastCommittedSize() uint64 { return c.lastCommitted.Load() }

func (c *Committer) loop(ctx context.Context) {
	defer close(c.done)
	t := time.NewTicker(c.interval)
	defer t.Stop()
	// Best-effort first commit so the dashboard isn't blank for the
	// whole first interval. Failures here are logged and retried.
	if _, _, err := c.commit(ctx); err != nil && !errors.Is(err, ErrTreeShrank) && !errors.Is(err, ErrEmptyTree) {
		c.logger.Warn("anchor: initial commit failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stop:
			return
		case <-t.C:
			if _, _, err := c.commit(ctx); err != nil &&
				!errors.Is(err, ErrTreeShrank) && !errors.Is(err, ErrEmptyTree) {
				c.logger.Warn("anchor: tick commit failed", "err", err)
			}
		}
	}
}

// commit is the unit of work: snapshot the tree, decide if we should
// broadcast, broadcast, update the store. ErrTreeShrank and
// ErrEmptyTree are returned (not logged) so the caller can treat them
// as non-events.
func (c *Committer) commit(ctx context.Context) (Anchor, bool, error) {
	size := c.tree.Size()
	if size == 0 {
		return Anchor{}, false, ErrEmptyTree
	}
	root := append([]byte(nil), c.tree.Root()...)
	if err := validateCommit(size, root); err != nil {
		return Anchor{}, false, err
	}
	if last := c.lastCommitted.Load(); size <= last {
		return Anchor{}, false, ErrTreeShrank
	}
	now := c.clock()
	receipt, err := c.client.Commit(ctx, size, root, now)
	if err != nil {
		return Anchor{}, false, formatErr(err, size, root)
	}
	a := Anchor{
		ID:          receipt.ID,
		TreeSize:    size,
		Root:        root,
		Timestamp:   now,
		BlockNumber: receipt.BlockNumber,
		TxHash:      receipt.TxHash,
	}
	c.store.Set(a)
	c.lastCommitted.Store(size)
	c.logger.Info(
		"anchor: committed",
		"id", a.ID,
		"tree_size", a.TreeSize,
		"root_hex", a.RootHex(),
		"tx_hash", a.TxHash,
		"block_number", a.BlockNumber,
	)
	return a, true, nil
}
