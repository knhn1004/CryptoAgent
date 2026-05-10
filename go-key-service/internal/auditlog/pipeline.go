// Package auditlog wires verified agent actions into the append-only
// Merkle tree. It owns the replay-protection cache (keyed by
// agent_id+nonce) and a fan-out of indexed events so downstream
// consumers (the dashboard, the on-chain anchor job) can tail the log.
//
// Per docs/schema.md, the leaf payload is canonical(action) || signature
// and the replay window is 30 s skew + 600 s nonce window.
//
// The pipeline emits two kinds of Events on its subscriber fan-out:
// "appended" for successfully verified actions that grew the Merkle
// tree, and "rejected" for actions that failed verification (or were
// denied by an external policy check, e.g. the capability service).
// Rejections never touch the tree; they exist purely so the dashboard
// can render real-time security highlights without a second feed.
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

// Event kinds emitted on the subscriber fan-out and persisted in the
// in-memory append log. Wire format keeps these as plain strings.
const (
	KindAppended = "appended"
	KindRejected = "rejected"
)

// Event is the indexed record emitted to subscribers and persisted in
// the in-memory append log. JSON tags match the dashboard contract.
//
// For Kind=="appended": LeafIndex, LeafHash, Action, Signature,
// PublicKey are all populated and the leaf is part of the Merkle tree.
//
// For Kind=="rejected": LeafHash/Signature/PublicKey are nil, LeafIndex
// is zero, Action may be nil (denials from non-Submit paths know only
// agent_id/action_type/target), and Reason carries a short stable code.
type Event struct {
	Seq        uint64            `json:"seq"`
	Kind       string            `json:"kind"`
	LeafIndex  uint64            `json:"leaf_index"`
	LeafHash   []byte            `json:"leaf_hash"`
	Action     *action.Action    `json:"action,omitempty"`
	Signature  []byte            `json:"signature"`
	PublicKey  ed25519.PublicKey `json:"public_key"`
	AgentID    string            `json:"agent_id,omitempty"`
	ActionType string            `json:"action_type,omitempty"`
	Target     string            `json:"target,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	RecordedAt time.Time         `json:"recorded_at"`
}

// MarshalJSON encodes the byte slices as hex so the dashboard can render
// them without an extra base64 step. Branches on Kind so rejected events
// don't carry empty leaf_hash/signature/public_key fields.
func (e Event) MarshalJSON() ([]byte, error) {
	if e.Kind == KindRejected {
		return json.Marshal(struct {
			Seq        uint64         `json:"seq"`
			Kind       string         `json:"kind"`
			Action     *action.Action `json:"action,omitempty"`
			AgentID    string         `json:"agent_id,omitempty"`
			ActionType string         `json:"action_type,omitempty"`
			Target     string         `json:"target,omitempty"`
			Reason     string         `json:"reason"`
			RecordedAt time.Time      `json:"recorded_at"`
		}{
			Seq:        e.Seq,
			Kind:       KindRejected,
			Action:     e.Action,
			AgentID:    e.AgentID,
			ActionType: e.ActionType,
			Target:     e.Target,
			Reason:     e.Reason,
			RecordedAt: e.RecordedAt,
		})
	}
	kind := e.Kind
	if kind == "" {
		kind = KindAppended
	}
	return json.Marshal(struct {
		Seq        uint64         `json:"seq"`
		Kind       string         `json:"kind"`
		LeafIndex  uint64         `json:"leaf_index"`
		LeafHash   string         `json:"leaf_hash"`
		Action     *action.Action `json:"action"`
		Signature  string         `json:"signature"`
		PublicKey  string         `json:"public_key"`
		RecordedAt time.Time      `json:"recorded_at"`
	}{
		Seq:        e.Seq,
		Kind:       kind,
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
//
// Every error path before return also broadcasts a Kind=="rejected"
// Event, so dashboard subscribers see denials in real time alongside
// successful appends.
func (p *Pipeline) Submit(ctx context.Context, a *action.Action, sig []byte) (*Event, bool, error) {
	if a == nil {
		return nil, false, ErrSchemaVersion
	}

	if a.SchemaVersion != action.SchemaVersion {
		p.recordRejectionFromAction(a, "schema_version")
		return nil, false, ErrSchemaVersion
	}
	if err := a.Validate(); err != nil {
		p.recordRejectionFromAction(a, rejectionReasonForValidate(err))
		return nil, false, err
	}

	now := p.now()
	if skew := absInt64(now.UnixMilli() - a.TimestampMs); skew > action.MaxSkewMillis {
		p.recordRejectionFromAction(a, "timestamp_skew")
		return nil, false, ErrTimestampSkew
	}

	pub, _, err := p.store.Get(ctx, a.AgentID)
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			p.recordRejectionFromAction(a, "unknown_agent")
			return nil, false, ErrUnknownAgent
		}
		return nil, false, err
	}

	if err := signing.Verify(a, sig, pub); err != nil {
		p.recordRejectionFromAction(a, "invalid_signature")
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
		Kind:       KindAppended,
		LeafIndex:  idx,
		LeafHash:   merkle.HashLeaf(leafPayload),
		Action:     copyAction(a),
		Signature:  copyBytes(sig),
		PublicKey:  copyBytes(pub),
		RecordedAt: now,
	}
	p.seen[key] = ev
	p.events = append(p.events, ev)
	ev.Seq = uint64(len(p.events) - 1)

	for _, ch := range p.subs {
		select {
		case ch <- *ev:
		default:
			// Subscriber too slow; drop. They can re-sync via EventsSince.
		}
	}

	return ev, true, nil
}

// RecordRejection logs an externally-detected denial — for example, a
// capability/token verify failure handled by a different service. The
// rejection is broadcast to subscribers and persisted in EventsSince.
func (p *Pipeline) RecordRejection(agentID, actionType, target, reason string) {
	ev := &Event{
		Kind:       KindRejected,
		AgentID:    agentID,
		ActionType: actionType,
		Target:     target,
		Reason:     reason,
		RecordedAt: p.now(),
	}
	p.publish(ev)
}

// recordRejectionFromAction is the internal Submit-path emitter. It
// pulls agent_id/action_type/target off the parsed action so dashboard
// rows still identify the actor.
func (p *Pipeline) recordRejectionFromAction(a *action.Action, reason string) {
	ev := &Event{
		Kind:       KindRejected,
		Action:     copyAction(a),
		AgentID:    a.AgentID,
		ActionType: a.ActionType,
		Target:     a.Target,
		Reason:     reason,
		RecordedAt: p.now(),
	}
	p.publish(ev)
}

func (p *Pipeline) publish(ev *Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, ev)
	ev.Seq = uint64(len(p.events) - 1)
	for _, ch := range p.subs {
		select {
		case ch <- *ev:
		default:
		}
	}
}

// rejectionReasonForValidate maps action.Validate errors to the short
// stable codes the dashboard renders. Anything unknown collapses to
// "invalid_action".
func rejectionReasonForValidate(err error) string {
	switch {
	case errors.Is(err, action.ErrEmptyField):
		return "invalid_action"
	case errors.Is(err, action.ErrNonceShape):
		return "invalid_nonce"
	case errors.Is(err, action.ErrSchemaVersion):
		return "schema_version"
	default:
		return "invalid_action"
	}
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

// EventsSince returns the appended events with LeafIndex >= since, in
// append order. Rejected events are filtered out — this is the
// historical contract auditors and the e2e suite rely on. Dashboard
// callers that want the unified feed (appended + rejected) use
// AllEventsSince instead.
func (p *Pipeline) EventsSince(since uint64) []Event {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Event
	for _, e := range p.events {
		if e.Kind != KindAppended {
			continue
		}
		if e.LeafIndex < since {
			continue
		}
		out = append(out, *e)
	}
	return out
}

// AllEventsSince returns appended + rejected events with Seq >= since,
// in record order. Used by the SSE handler to backfill the dashboard
// after reconnect. Seq is monotonic across both event kinds; the
// dashboard caches the last-seen Seq and passes it as `since` on
// reconnect.
func (p *Pipeline) AllEventsSince(since uint64) []Event {
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

// Size reports the number of appended events — equivalently, the
// Merkle tree size. Rejected events are not counted; they have no
// leaf. Use AllEventsSince/len() to count the unified feed.
func (p *Pipeline) Size() uint64 {
	return p.tree.Size()
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
