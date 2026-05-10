package auditlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keystore"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/merkle"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/signing"
)

// fixedClock returns a constant time so tests can construct actions with
// stable timestamps and not race the wall clock.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// newAgent registers an agent in the store and returns its keys + id.
func newAgent(t *testing.T, store keystore.KeyStore, id string) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	if _, err := store.Create(context.Background(), id); err != nil {
		t.Fatalf("create agent: %v", err)
	}
	pub, priv, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get agent: %v", err)
	}
	return pub, priv
}

func randNonce(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b[:])
}

func makeAction(agentID string, tsMs int64, nonce string) *action.Action {
	return &action.Action{
		SchemaVersion: action.SchemaVersion,
		AgentID:       agentID,
		ActionType:    "ping",
		Target:        "peer-002",
		TimestampMs:   tsMs,
		Nonce:         nonce,
	}
}

func newPipelineAt(t *testing.T, now time.Time) (*Pipeline, keystore.KeyStore, *merkle.Tree) {
	t.Helper()
	store := keystore.NewMemory()
	tree := merkle.New()
	p := New(tree, store, WithClock(fixedClock(now)))
	return p, store, tree
}

func TestSubmitHappyPath(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, tree := newPipelineAt(t, now)
	_, priv := newAgent(t, store, "agent-1")

	a := makeAction("agent-1", now.UnixMilli(), randNonce(t))
	sig, err := signing.Sign(a, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	ev, fresh, err := p.Submit(context.Background(), a, sig)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if !fresh {
		t.Fatal("expected fresh=true on first submit")
	}
	if ev.LeafIndex != 0 {
		t.Fatalf("leaf index: got %d want 0", ev.LeafIndex)
	}
	if tree.Size() != 1 {
		t.Fatalf("tree size: got %d want 1", tree.Size())
	}

	canon, err := a.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := merkle.HashLeaf(append(canon, sig...))
	if !bytes.Equal(ev.LeafHash, want) {
		t.Fatalf("leaf hash mismatch:\n got  %x\n want %x", ev.LeafHash, want)
	}
	if !bytes.Equal(ev.Signature, sig) {
		t.Fatal("event signature mismatch")
	}
	if ev.Action == nil || ev.Action.AgentID != "agent-1" {
		t.Fatalf("event action wrong: %+v", ev.Action)
	}
	if ev.RecordedAt.IsZero() {
		t.Fatal("RecordedAt unset")
	}
}

func TestSubmitIdempotentSameAction(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, tree := newPipelineAt(t, now)
	_, priv := newAgent(t, store, "agent-1")

	a := makeAction("agent-1", now.UnixMilli(), randNonce(t))
	sig, err := signing.Sign(a, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	first, fresh1, err := p.Submit(context.Background(), a, sig)
	if err != nil || !fresh1 {
		t.Fatalf("first submit: fresh=%v err=%v", fresh1, err)
	}
	second, fresh2, err := p.Submit(context.Background(), a, sig)
	if err != nil {
		t.Fatalf("second submit err: %v", err)
	}
	if fresh2 {
		t.Fatal("expected fresh=false on duplicate submit")
	}
	if first.LeafIndex != second.LeafIndex {
		t.Fatalf("idempotent leaf index: got %d want %d", second.LeafIndex, first.LeafIndex)
	}
	if !bytes.Equal(first.LeafHash, second.LeafHash) {
		t.Fatal("idempotent leaf hash mismatch")
	}
	if tree.Size() != 1 {
		t.Fatalf("tree grew on duplicate: size %d", tree.Size())
	}
}

func TestSubmitIdempotentSameAgentNonceDifferentAction(t *testing.T) {
	// Per spec: replay protection keys on (agent_id, nonce). Resubmitting
	// the same nonce — even with a different action body — returns the
	// originally recorded event without appending.
	now := time.UnixMilli(1_700_000_000_000)
	p, store, tree := newPipelineAt(t, now)
	_, priv := newAgent(t, store, "agent-1")

	nonce := randNonce(t)
	a1 := makeAction("agent-1", now.UnixMilli(), nonce)
	sig1, _ := signing.Sign(a1, priv)
	first, _, err := p.Submit(context.Background(), a1, sig1)
	if err != nil {
		t.Fatalf("first submit: %v", err)
	}

	a2 := makeAction("agent-1", now.UnixMilli(), nonce)
	a2.Target = "different-peer"
	sig2, _ := signing.Sign(a2, priv)
	second, fresh, err := p.Submit(context.Background(), a2, sig2)
	if err != nil {
		t.Fatalf("second submit: %v", err)
	}
	if fresh {
		t.Fatal("expected nonce collision to be treated as duplicate")
	}
	if second.LeafIndex != first.LeafIndex {
		t.Fatalf("expected cached event returned, got new index %d", second.LeafIndex)
	}
	if tree.Size() != 1 {
		t.Fatalf("tree grew on nonce collision: size %d", tree.Size())
	}
}

func TestSubmitUnknownAgent(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, _ := newPipelineAt(t, now)
	// Register a different agent so we have keys to sign with.
	_, priv := newAgent(t, store, "agent-x")

	a := makeAction("agent-missing", now.UnixMilli(), randNonce(t))
	sig, _ := signing.Sign(a, priv)

	_, _, err := p.Submit(context.Background(), a, sig)
	if !errors.Is(err, ErrUnknownAgent) {
		t.Fatalf("err: got %v want ErrUnknownAgent", err)
	}
}

func TestSubmitBadSignature(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, tree := newPipelineAt(t, now)
	newAgent(t, store, "agent-1")

	a := makeAction("agent-1", now.UnixMilli(), randNonce(t))
	bad := make([]byte, ed25519.SignatureSize)
	_, _, err := p.Submit(context.Background(), a, bad)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err: got %v want ErrInvalidSignature", err)
	}
	if tree.Size() != 0 {
		t.Fatalf("tree mutated on bad sig: size %d", tree.Size())
	}
}

func TestSubmitTimestampSkew(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, _ := newPipelineAt(t, now)
	_, priv := newAgent(t, store, "agent-1")

	skewed := now.Add(action.MaxSkewMillis*time.Millisecond + time.Second).UnixMilli()
	a := makeAction("agent-1", skewed, randNonce(t))
	sig, _ := signing.Sign(a, priv)

	_, _, err := p.Submit(context.Background(), a, sig)
	if !errors.Is(err, ErrTimestampSkew) {
		t.Fatalf("err: got %v want ErrTimestampSkew", err)
	}
}

func TestSubmitSchemaVersionRejected(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, _ := newPipelineAt(t, now)
	newAgent(t, store, "agent-1")

	a := makeAction("agent-1", now.UnixMilli(), randNonce(t))
	a.SchemaVersion = 99
	// Cannot Sign (Validate will reject); craft a sig manually so the
	// pipeline encounters the schema check, not a signing error.
	sig := make([]byte, ed25519.SignatureSize)
	_, _, err := p.Submit(context.Background(), a, sig)
	if !errors.Is(err, ErrSchemaVersion) {
		t.Fatalf("err: got %v want ErrSchemaVersion", err)
	}
}

func TestSubscriberReceivesEvent(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, _ := newPipelineAt(t, now)
	_, priv := newAgent(t, store, "agent-1")

	ch, cancel := p.Subscribe()
	defer cancel()

	a := makeAction("agent-1", now.UnixMilli(), randNonce(t))
	sig, _ := signing.Sign(a, priv)
	if _, _, err := p.Submit(context.Background(), a, sig); err != nil {
		t.Fatalf("submit: %v", err)
	}

	select {
	case ev := <-ch:
		if ev.LeafIndex != 0 {
			t.Fatalf("event index: got %d", ev.LeafIndex)
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive event")
	}
}

func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, _ := newPipelineAt(t, now)
	_, priv := newAgent(t, store, "agent-1")

	// Subscribe but never read. Pipeline must not block when the buffer fills.
	_, cancel := p.Subscribe()
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 64; i++ {
			a := makeAction("agent-1", now.UnixMilli(), randNonce(t))
			sig, _ := signing.Sign(a, priv)
			if _, _, err := p.Submit(context.Background(), a, sig); err != nil {
				t.Errorf("submit %d: %v", i, err)
				return
			}
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("pipeline blocked on slow subscriber")
	}
}

func TestConcurrentSubmittersNoDoubleAppend(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, tree := newPipelineAt(t, now)
	_, priv := newAgent(t, store, "agent-1")

	const submitters = 16
	a := makeAction("agent-1", now.UnixMilli(), randNonce(t))
	sig, _ := signing.Sign(a, priv)

	var wg sync.WaitGroup
	wg.Add(submitters)
	for i := 0; i < submitters; i++ {
		go func() {
			defer wg.Done()
			if _, _, err := p.Submit(context.Background(), a, sig); err != nil {
				t.Errorf("submit: %v", err)
			}
		}()
	}
	wg.Wait()
	if tree.Size() != 1 {
		t.Fatalf("expected exactly one append, got tree size %d", tree.Size())
	}
}

func TestSubscribeCancelStopsDelivery(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, _ := newPipelineAt(t, now)
	_, priv := newAgent(t, store, "agent-1")

	ch, cancel := p.Subscribe()
	cancel()

	a := makeAction("agent-1", now.UnixMilli(), randNonce(t))
	sig, _ := signing.Sign(a, priv)
	if _, _, err := p.Submit(context.Background(), a, sig); err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Channel should be closed; either the receive sees !ok promptly or we
	// time out indicating it is still open (a bug).
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel closed after cancel")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("channel not closed after cancel")
	}
}

func TestSubmitBroadcastsRejectionOnBadSignature(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, _ := newPipelineAt(t, now)
	newAgent(t, store, "agent-1")

	ch, cancel := p.Subscribe()
	defer cancel()

	a := makeAction("agent-1", now.UnixMilli(), randNonce(t))
	bad := make([]byte, ed25519.SignatureSize)
	if _, _, err := p.Submit(context.Background(), a, bad); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("submit err: got %v want ErrInvalidSignature", err)
	}

	select {
	case ev := <-ch:
		if ev.Kind != KindRejected {
			t.Fatalf("kind: got %q want %q", ev.Kind, KindRejected)
		}
		if ev.Reason != "invalid_signature" {
			t.Fatalf("reason: got %q want invalid_signature", ev.Reason)
		}
		if ev.AgentID != "agent-1" {
			t.Fatalf("agent_id: got %q", ev.AgentID)
		}
		if ev.LeafHash != nil {
			t.Fatalf("rejection should have no leaf hash")
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive rejection event")
	}
}

func TestRecordRejectionBroadcastsAndPersists(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, _, _ := newPipelineAt(t, now)

	ch, cancel := p.Subscribe()
	defer cancel()

	p.RecordRejection("agent-x", "transfer_funds", "treasury", "expired")

	select {
	case ev := <-ch:
		if ev.Kind != KindRejected || ev.Reason != "expired" || ev.AgentID != "agent-x" {
			t.Fatalf("event: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}

	got := p.AllEventsSince(0)
	if len(got) != 1 || got[0].Kind != KindRejected {
		t.Fatalf("AllEventsSince: %+v", got)
	}
	if got[0].Seq != 0 {
		t.Fatalf("seq: got %d want 0", got[0].Seq)
	}

	// EventsSince filters out rejections — historical contract.
	if appendedOnly := p.EventsSince(0); len(appendedOnly) != 0 {
		t.Fatalf("EventsSince should hide rejections, got %+v", appendedOnly)
	}
}

func TestEventsSinceReplay(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	p, store, _ := newPipelineAt(t, now)
	_, priv := newAgent(t, store, "agent-1")

	for i := 0; i < 3; i++ {
		a := makeAction("agent-1", now.UnixMilli(), randNonce(t))
		sig, _ := signing.Sign(a, priv)
		if _, _, err := p.Submit(context.Background(), a, sig); err != nil {
			t.Fatalf("submit: %v", err)
		}
	}

	got := p.EventsSince(0)
	if len(got) != 3 {
		t.Fatalf("len: got %d want 3", len(got))
	}
	got = p.EventsSince(2)
	if len(got) != 1 || got[0].LeafIndex != 2 {
		t.Fatalf("since=2: %+v", got)
	}
}
