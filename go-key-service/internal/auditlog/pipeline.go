// Package auditlog wires verified agent actions into the append-only
// Merkle tree. It owns the replay-protection cache (keyed by
// agent_id+nonce) and a fan-out of indexed events so downstream
// consumers (the dashboard, the on-chain anchor job) can tail the log.
//
// Per docs/schema.md, the leaf payload is canonical(action) || signature
// and the replay window is 30 s skew + 600 s nonce window.
package auditlog

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keystore"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/merkle"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/signing"
)

// Sentinel errors. ErrInvalidSignature wraps the signing package's value
// so callers can errors.Is against either.
var (
	ErrSchemaVersion    = action.ErrSchemaVersion
	ErrTimestampSkew    = errors.New("auditlog: timestamp outside accepted skew window")
	ErrUnknownAgent     = errors.New("auditlog: unknown agent")
	ErrInvalidSignature = signing.ErrInvalidSignature
)

// Event is the indexed record emitted to subscribers and persisted in
// the in-memory append log. JSON tags match the dashboard contract.
type Event struct {
	LeafIndex  uint64            `json:"leaf_index"`
	LeafHash   []byte            `json:"leaf_hash"`
	Action     *action.Action    `json:"action"`
	Signature  []byte            `json:"signature"`
	PublicKey  ed25519.PublicKey `json:"public_key"`
	RecordedAt time.Time         `json:"recorded_at"`
}

// MarshalJSON encodes the byte slices as hex so the dashboard can render
// them without an extra base64 step.
func (e Event) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		LeafIndex  uint64         `json:"leaf_index"`
		LeafHash   string         `json:"leaf_hash"`
		Action     *action.Action `json:"action"`
		Signature  string         `json:"signature"`
		PublicKey  string         `json:"public_key"`
		RecordedAt time.Time      `json:"recorded_at"`
	}{
		LeafIndex:  e.LeafIndex,
		LeafHash:   hexEncode(e.LeafHash),
		Action:     e.Action,
		Signature:  hexEncode(e.Signature),
		PublicKey:  hexEncode(e.PublicKey),
		RecordedAt: e.RecordedAt,
	})
}

// Option configures the Pipeline at construction time.
type Option func(*Pipeline)

// WithClock injects a clock; tests pin time, production uses time.Now.
func WithClock(now func() time.Time) Option {
	return func(p *Pipeline) {
		if now != nil {
			p.now = now
		}
	}
}

// WithSubscriberBuffer overrides the per-subscriber channel buffer size.
func WithSubscriberBuffer(n int) Option {
	return func(p *Pipeline) {
		if n > 0 {
			p.subBuffer = n
		}
	}
}

// Pipeline verifies signed actions and appends them to a Merkle tree.
//
// Idempotency: a small map keyed by (agent_id, nonce) caches the first
// Event observed for each pair. Entries are evicted lazily on read once
// they fall outside the replay window (skew + nonce window). This keeps
// the implementation simple — no background goroutine — at the cost of
// holding stale entries until a duplicate query touches them. For the
// expected throughput of this service that trade-off is acceptable.
//
// Back-pressure: each subscriber gets a small buffered channel. If the
// buffer is full, the pipeline drops the event for that subscriber
// rather than blocking the append path. Slow consumers therefore lose
// events; they should re-sync via EventsSince on reconnect.
type Pipeline struct {
	tree  *merkle.Tree
	store keystore.KeyStore
	now   func() time.Time

	subBuffer int

	mu   sync.Mutex
	seen map[string]*Event
	// events retains every appended Event so EventsSince() can backfill
	// reconnecting subscribers. Bounded only by process lifetime — fine
	// for the in-memory scope of the current service. A ring buffer or an
	// external store is the right next step before a long-running
	// production deployment.
	events []*Event
	subs   map[uint64]chan Event
	nextID uint64
}

// New constructs a Pipeline. Both tree and store are required.
func New(tree *merkle.Tree, store keystore.KeyStore, opts ...Option) *Pipeline {
	p := &Pipeline{
		tree:      tree,
		store:     store,
		now:       time.Now,
		subBuffer: 16,
		seen:      make(map[string]*Event),
		subs:      make(map[uint64]chan Event),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Submit verifies and appends the action. The bool return is true when
// a new leaf was appended, false when the call hit the idempotency cache
// (in which case the cached Event is returned with a nil error).
func (p *Pipeline) Submit(ctx context.Context, a *action.Action, sig []byte) (*Event, bool, error) {
	if a == nil {
		return nil, false, ErrSchemaVersion
	}

	if a.SchemaVersion != action.SchemaVersion {
		return nil, false, ErrSchemaVersion
	}
	if err := a.Validate(); err != nil {
		return nil, false, err
	}

	now := p.now()
	if skew := absInt64(now.UnixMilli() - a.TimestampMs); skew > action.MaxSkewMillis {
		return nil, false, ErrTimestampSkew
	}

	pub, _, err := p.store.Get(ctx, a.AgentID)
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return nil, false, ErrUnknownAgent
		}
		return nil, false, err
	}

	if err := signing.Verify(a, sig, pub); err != nil {
		return nil, false, err
	}

	canon, err := a.Canonical()
	if err != nil {
		return nil, false, err
	}

	key := replayKey(a.AgentID, a.Nonce)

	p.mu.Lock()
	defer p.mu.Unlock()

	if cached, ok := p.seen[key]; ok {
		if !p.expired(cached.RecordedAt, now) {
			return cached, false, nil
		}
		// Stale — fall through and treat as a fresh append.
		delete(p.seen, key)
	}

	leafPayload := make([]byte, 0, len(canon)+len(sig))
	leafPayload = append(leafPayload, canon...)
	leafPayload = append(leafPayload, sig...)

	idx, err := p.tree.Append(leafPayload)
	if err != nil {
		return nil, false, fmt.Errorf("auditlog: tree append: %w", err)
	}
	ev := &Event{
		LeafIndex:  idx,
		LeafHash:   merkle.HashLeaf(leafPayload),
		Action:     copyAction(a),
		Signature:  copyBytes(sig),
		PublicKey:  copyBytes(pub),
		RecordedAt: now,
	}
	p.seen[key] = ev
	p.events = append(p.events, ev)

	for _, ch := range p.subs {
		select {
		case ch <- *ev:
		default:
			// Subscriber too slow; drop. They can re-sync via EventsSince.
		}
	}

	return ev, true, nil
}

// Subscribe registers a new subscriber and returns its channel plus a
// cancel function. The cancel function unregisters the subscriber and
// closes the channel; it is safe to call more than once.
func (p *Pipeline) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, p.subBuffer)
	p.mu.Lock()
	id := p.nextID
	p.nextID++
	p.subs[id] = ch
	p.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			p.mu.Lock()
			if c, ok := p.subs[id]; ok {
				delete(p.subs, id)
				close(c)
			}
			p.mu.Unlock()
		})
	}
	return ch, cancel
}

// EventsSince returns all events with leaf index >= since, in append
// order. Used by the SSE handler to backfill before tailing live events.
func (p *Pipeline) EventsSince(since uint64) []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	if since >= uint64(len(p.events)) {
		return nil
	}
	out := make([]Event, 0, uint64(len(p.events))-since)
	for _, e := range p.events[since:] {
		out = append(out, *e)
	}
	return out
}

// Size reports the current number of recorded events. Equal to tree size.
func (p *Pipeline) Size() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return uint64(len(p.events))
}

func (p *Pipeline) expired(recordedAt, now time.Time) bool {
	window := time.Duration(action.MaxSkewMillis+action.NonceWindowMs) * time.Millisecond
	return now.Sub(recordedAt) > window
}

func replayKey(agentID, nonce string) string {
	return agentID + "|" + nonce
}

func copyBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func copyAction(a *action.Action) *action.Action {
	if a == nil {
		return nil
	}
	cp := *a
	return &cp
}

func absInt64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// hexEncode is split out so we don't pull encoding/hex into the hot path
// for callers that never marshal. Tiny enough to inline.
func hexEncode(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
