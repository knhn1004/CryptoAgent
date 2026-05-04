// Package e2e wires together the audit pipeline, the keystore, and
// the Merkle tree the way `cmd/keyserver` does, then drives them
// through every adversarial scenario the project proposal calls
// out as a success metric.
//
// The suite is the home for two of the four metrics from
// docs/proposal:
//
//   - 100% of agent messages signed and verified end-to-end.
//   - Tampering past a leaf produces a detectable root mismatch
//     against any historical anchor (RFC 6962 consistency).
//
// The other two metrics (multi-sig bypass count, ACL rejection
// count) live in the SDK side at sdk-python/tests/test_e2e_success_metrics.py
// because they're orchestrator-level checks that exercise decorators
// the agent code calls into.
package e2e

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/knhn1004/CryptoAgent/go-key-service/internal/action"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/auditlog"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/keystore"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/merkle"
	"github.com/knhn1004/CryptoAgent/go-key-service/internal/signing"
)

// fixedClock returns a clock function pinned at ts so timestamp skew
// checks pass deterministically.
func fixedClock(ts time.Time) func() time.Time { return func() time.Time { return ts } }

// makeAction builds a canonical Action whose timestamp is exactly
// `nowMs`, so the pipeline's skew check is happy when the pipeline
// clock is also pinned to nowMs.
func makeAction(agentID, actionType, target, nonce string, nowMs int64) *action.Action {
	return &action.Action{
		SchemaVersion: action.SchemaVersion,
		AgentID:       agentID,
		ActionType:    actionType,
		Target:        target,
		TimestampMs:   nowMs,
		Nonce:         nonce,
	}
}

// nonces yields N distinct 32-char lowercase hex nonces.
func nonces(n int) []string {
	out := make([]string, n)
	const hex = "0123456789abcdef"
	for i := 0; i < n; i++ {
		var buf [32]byte
		v := uint64(i + 1)
		for j := 31; j >= 0; j-- {
			buf[j] = hex[v&0xF]
			v >>= 4
		}
		out[i] = string(buf[:])
	}
	return out
}

// Metric 1 — every signed action submitted to the pipeline is
// verified and lands in the Merkle log; every forged signature is
// rejected. The success criterion is "100% of accepted actions are
// verified", which we assert as: tree size == accepted == verified
// submissions, and forged submissions never grow the tree.
func TestE2E_AllSignedActionsAreVerified(t *testing.T) {
	const honestN = 50
	const forgedN = 10
	ts := time.UnixMilli(1_700_000_000_000).UTC()

	store := keystore.NewMemory()
	tree := merkle.New()
	pipe := auditlog.New(tree, store, auditlog.WithClock(fixedClock(ts)))

	ctx := context.Background()
	if _, err := store.Create(ctx, "alice"); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	_, alicePriv, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatalf("get alice: %v", err)
	}

	// Plant a separate keypair we'll use to forge signatures over the
	// same canonical bytes — they must never verify against alice's pubkey.
	_, attackerPriv, err := signing.GenerateKey(nil)
	if err != nil {
		t.Fatalf("attacker key: %v", err)
	}

	ns := nonces(honestN + forgedN)

	accepted := 0
	for i := 0; i < honestN; i++ {
		a := makeAction("alice", "transfer_funds", "vault/treasury", ns[i], ts.UnixMilli())
		sig, err := signing.Sign(a, alicePriv)
		if err != nil {
			t.Fatalf("sign honest %d: %v", i, err)
		}
		ev, isNew, err := pipe.Submit(ctx, a, sig)
		if err != nil {
			t.Fatalf("submit honest %d: %v", i, err)
		}
		if !isNew || ev == nil {
			t.Fatalf("honest %d: expected fresh append", i)
		}
		accepted++
	}

	// Forged: same agent_id but signed with a different private key.
	rejected := 0
	for i := 0; i < forgedN; i++ {
		a := makeAction("alice", "transfer_funds", "vault/treasury", ns[honestN+i], ts.UnixMilli())
		sig, err := signing.Sign(a, attackerPriv)
		if err != nil {
			t.Fatalf("sign forged %d: %v", i, err)
		}
		_, _, err = pipe.Submit(ctx, a, sig)
		if !errors.Is(err, signing.ErrInvalidSignature) {
			t.Fatalf("forged %d: want ErrInvalidSignature, got %v", i, err)
		}
		rejected++
	}

	gotSize := pipe.Size()
	if gotSize != uint64(accepted) {
		t.Fatalf("audit-log size mismatch: tree=%d accepted=%d", gotSize, accepted)
	}
	if uint64(tree.Size()) != gotSize {
		t.Fatalf("tree/pipeline size mismatch: tree=%d pipe=%d", tree.Size(), gotSize)
	}
	if rejected != forgedN {
		t.Fatalf("forged-rejection count mismatch: got %d want %d", rejected, forgedN)
	}

	// 100% verified-rate over the appended set: every event in the log
	// has a signature that re-verifies against the store-held pubkey.
	pub, _, err := store.Get(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	events := pipe.EventsSince(0)
	if len(events) != accepted {
		t.Fatalf("EventsSince mismatch: got %d want %d", len(events), accepted)
	}
	for i, ev := range events {
		if err := signing.Verify(ev.Action, ev.Signature, pub); err != nil {
			t.Fatalf("event %d failed re-verify: %v", i, err)
		}
		// Replay protection on the same nonce must not allow a second append.
		_, isNew, err := pipe.Submit(ctx, ev.Action, ev.Signature)
		if err != nil {
			t.Fatalf("replay submit %d: %v", i, err)
		}
		if isNew {
			t.Fatalf("event %d: replay grew the tree (replay protection broken)", i)
		}
	}

	t.Logf("metric 1: signed+verified=%d/%d (100%%); forged rejections=%d", accepted, accepted, rejected)
}

// Metric 3 — tampering past a historical leaf is detected by the
// consistency verifier with a hex-bearing diagnostic. Covers the
// adversarial scenario from docs/threat_model.md T7: a compromised
// log operator presents a *rewritten* live tree that disagrees with
// an externally-anchored historical root.
//
// We model the rewrite by building two trees: the honest one supplies
// the historical root snapshot; the adversarial one is what the
// verifier sees. The verifier MUST refuse with a non-empty diagnostic
// message and either ErrRootMismatch or ErrInvalidProof.
func TestE2E_TamperedLeafIsDetected(t *testing.T) {
	const historicalSize = uint64(8)
	const liveSize = uint64(16)

	honest := merkle.New()
	for i := 0; i < int(liveSize); i++ {
		if _, err := honest.Append([]byte{byte(i)}); err != nil {
			t.Fatalf("honest append %d: %v", i, err)
		}
	}
	historicalRoot, err := honest.RootAt(historicalSize)
	if err != nil {
		t.Fatalf("RootAt: %v", err)
	}

	// Sanity: verifying the snapshot against the *honest* live tree must succeed.
	if rep, err := merkle.NewVerifier(honest).VerifyHistoricalRoot(historicalRoot, historicalSize); err != nil || !rep.OK {
		t.Fatalf("honest verifier must accept snapshot: err=%v report=%+v", err, rep)
	}

	// Adversary publishes a tree where leaf 3 has been swapped for
	// different content. Same RFC 6962 leaf hashing, well-formed
	// structure — the only thing wrong is that one byte changed.
	adversary := merkle.New()
	for i := 0; i < int(liveSize); i++ {
		payload := []byte{byte(i)}
		if i == 3 {
			payload = []byte{0xFF}
		}
		if _, err := adversary.Append(payload); err != nil {
			t.Fatalf("adversary append %d: %v", i, err)
		}
	}

	report, err := merkle.NewVerifier(adversary).VerifyHistoricalRoot(historicalRoot, historicalSize)
	if err == nil {
		t.Fatal("verifier must reject rewritten tree, got nil error")
	}
	if !errors.Is(err, merkle.ErrRootMismatch) && !errors.Is(err, merkle.ErrInvalidProof) {
		t.Fatalf("expected ErrRootMismatch or ErrInvalidProof, got %v", err)
	}
	if report == nil {
		t.Fatal("report should be non-nil even on failure")
	}
	if report.OK {
		t.Fatalf("report.OK must be false, got %+v", report)
	}
	if report.HistoricalRoot == "" || report.LiveRoot == "" || report.HistoricalRoot == report.LiveRoot {
		t.Fatalf("diagnostic must surface distinct hex roots, got %+v", report)
	}
	if report.Message == "" {
		t.Fatal("report.Message must be non-empty for the dashboard to display")
	}
	t.Logf("metric 3: tamper detected: %s historical=%s live=%s", report.Message, report.HistoricalRoot, report.LiveRoot)
}
