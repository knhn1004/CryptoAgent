from __future__ import annotations

import threading
import time

import pytest

from cryptoagent.action import Action
from cryptoagent.multisig import Gate, ThresholdNotMetError
from cryptoagent.proposal import (
    AuditSink,
    InMemoryAuditSink,
    LocalPeer,
    MerkleHTTPAuditSink,
    Proposal,
    ProposalError,
    ProposalFlow,
    ReplayError,
)
from cryptoagent.signing import generate_keypair, sign


def make_action(action_type: str = "transfer_funds", nonce: str | None = None) -> Action:
    return Action(
        schema_version=1,
        agent_id="agent-001",
        action_type=action_type,
        target="treasury",
        timestamp_ms=1_700_000_000_000,
        nonce=nonce or "0123456789abcdef0123456789abcdef",
    )


def make_proposer() -> tuple[bytes, bytes, str]:
    pub, priv = generate_keypair()
    return pub, priv, "proposer-1"


def make_proposal(action: Action | None = None) -> tuple[Proposal, bytes]:
    a = action or make_action()
    pub, priv, pid = make_proposer()
    flow = ProposalFlow(Gate({a.action_type: 1}), InMemoryAuditSink())
    proposal = flow.propose(a, priv, pub, pid)
    return proposal, priv


# ---------- Proposal.validate ----------------------------------------------


def test_proposal_validate_happy_and_bad_sig():
    a = make_action()
    pub, priv, pid = make_proposer()
    sig = sign(a, priv)
    p = Proposal(
        action=a,
        proposer_id=pid,
        proposer_pub=pub,
        proposer_sig=sig,
        created_at_ms=1_700_000_000_000,
    )
    p.validate()  # ok

    forged = Proposal(
        action=a,
        proposer_id=pid,
        proposer_pub=pub,
        proposer_sig=b"\x00" * 64,
        created_at_ms=1_700_000_000_000,
    )
    with pytest.raises(ProposalError):
        forged.validate()

    wrong_len = Proposal(
        action=a,
        proposer_id=pid,
        proposer_pub=pub,
        proposer_sig=b"\x00" * 10,
        created_at_ms=1_700_000_000_000,
    )
    with pytest.raises(ProposalError):
        wrong_len.validate()


# ---------- collect_signatures ---------------------------------------------


def _flow(threshold: int = 2, action_type: str = "transfer_funds") -> ProposalFlow:
    return ProposalFlow(Gate({action_type: threshold}), InMemoryAuditSink())


def test_collect_signatures_happy_path():
    a = make_action()
    flow = _flow(threshold=3)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)

    peers = [LocalPeer(*generate_keypair_with_id(f"peer-{i}")) for i in range(2)]
    sigs = flow.collect_signatures(proposal, peers, timeout_s=2.0)
    # Proposer + 2 peers = 3 entries.
    assert len(sigs) == 3
    pubs = {pub for pub, _ in sigs}
    assert proposal.proposer_pub in pubs


def test_collect_signatures_dedupes_same_peer_pub():
    a = make_action()
    flow = _flow(threshold=2)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)

    peer_pub, peer_priv = generate_keypair()
    p1 = LocalPeer("peer-A", peer_pub, peer_priv)
    p2 = LocalPeer("peer-A-dup", peer_pub, peer_priv)  # same pub, different id
    sigs = flow.collect_signatures(proposal, [p1, p2], timeout_s=2.0)
    pubs = [pub for pub, _ in sigs]
    # Proposer + the deduped peer pub == 2.
    assert len(sigs) == 2
    assert pubs.count(peer_pub) == 1


def test_collect_signatures_timeout():
    a = make_action()
    flow = _flow(threshold=2)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)

    fast_pub, fast_priv = generate_keypair()
    slow_pub, slow_priv = generate_keypair()
    fast = LocalPeer("fast", fast_pub, fast_priv)
    slow = SlowLocalPeer("slow", slow_pub, slow_priv, delay_s=2.0)

    start = time.monotonic()
    sigs = flow.collect_signatures(proposal, [fast, slow], timeout_s=0.3)
    elapsed = time.monotonic() - start
    pubs = {pub for pub, _ in sigs}
    assert fast_pub in pubs
    assert slow_pub not in pubs
    # Total wall time bounded near the timeout, not the slow peer's delay.
    assert elapsed < 1.5


def test_collect_signatures_invalid_peer_sig_dropped():
    a = make_action()
    flow = _flow(threshold=2)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)

    bad_pub, bad_priv = generate_keypair()
    bad = ConstantSigPeer("bad", bad_pub, bad_priv, sig=b"\x00" * 64)
    sigs = flow.collect_signatures(proposal, [bad], timeout_s=2.0)
    pubs = {pub for pub, _ in sigs}
    assert bad_pub not in pubs
    assert len(sigs) == 1  # only the proposer


def test_collect_signatures_peer_raises_is_skipped():
    a = make_action()
    flow = _flow(threshold=2)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)

    boom_pub, boom_priv = generate_keypair()
    boom = RaisingPeer("boom", boom_pub, boom_priv)
    sigs = flow.collect_signatures(proposal, [boom], timeout_s=2.0)
    assert len(sigs) == 1  # proposer only, peer crash swallowed


def test_collect_signatures_peer_returns_none_is_skipped():
    a = make_action()
    flow = _flow(threshold=2)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)

    abst_pub, abst_priv = generate_keypair()
    abst = AbstainPeer("abst", abst_pub, abst_priv)
    sigs = flow.collect_signatures(proposal, [abst], timeout_s=2.0)
    assert len(sigs) == 1


# ---------- execute --------------------------------------------------------


def test_execute_happy_path_runs_fn_and_audits_accepted():
    a = make_action()
    audit = InMemoryAuditSink()
    flow = ProposalFlow(Gate({a.action_type: 2}), audit)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)
    peer = LocalPeer(*generate_keypair_with_id("peer-1"))
    sigs = flow.collect_signatures(proposal, [peer], timeout_s=2.0)

    result = flow.execute(proposal, sigs, lambda x: x * 2, 21)
    assert result == 42
    assert len(audit.entries) == 1
    entry = audit.entries[0]
    assert entry["accepted"] is True
    assert entry["proposal"] is proposal


def test_execute_insufficient_sigs_rejects_and_audits():
    a = make_action()
    audit = InMemoryAuditSink()
    flow = ProposalFlow(Gate({a.action_type: 5}), audit)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)
    sigs = [(proposal.proposer_pub, proposal.proposer_sig)]

    with pytest.raises(ThresholdNotMetError):
        flow.execute(proposal, sigs, lambda: "boom")
    assert audit.entries[-1]["accepted"] is False
    assert audit.entries[-1]["reason"] == "threshold_not_met"


def test_execute_forged_sig_does_not_count():
    """Peer signs a DIFFERENT action; gate must reject."""
    a = make_action()
    audit = InMemoryAuditSink()
    flow = ProposalFlow(Gate({a.action_type: 2}), audit)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)

    # Peer signs a different action — sig is well-formed but for the wrong message.
    other = make_action(nonce="ffffffffffffffffffffffffffffffff")
    forge_pub, forge_priv = generate_keypair()
    forged_sig = sign(other, forge_priv)
    sigs = [
        (proposal.proposer_pub, proposal.proposer_sig),
        (forge_pub, forged_sig),
    ]
    with pytest.raises(ThresholdNotMetError):
        flow.execute(proposal, sigs, lambda: "x")
    assert audit.entries[-1]["accepted"] is False
    assert audit.entries[-1]["reason"] == "threshold_not_met"


def test_execute_replay_blocks_second_run():
    a = make_action()
    audit = InMemoryAuditSink()
    flow = ProposalFlow(Gate({a.action_type: 1}), audit)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)
    sigs = flow.collect_signatures(proposal, [], timeout_s=1.0)

    flow.execute(proposal, sigs, lambda: "ok")
    with pytest.raises(ReplayError):
        flow.execute(proposal, sigs, lambda: "ok")

    reasons = [e["reason"] for e in audit.entries]
    assert reasons[-1] == "replay"
    assert audit.entries[-1]["accepted"] is False


def test_audit_sink_failure_does_not_break_flow():
    a = make_action()
    sink = ExplodingAuditSink()
    flow = ProposalFlow(Gate({a.action_type: 1}), sink)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)
    sigs = [(proposal.proposer_pub, proposal.proposer_sig)]

    # Should NOT raise even though the sink does.
    assert flow.execute(proposal, sigs, lambda: "ok") == "ok"


def test_propose_and_run_end_to_end():
    a = make_action()
    audit = InMemoryAuditSink()
    flow = ProposalFlow(Gate({a.action_type: 2}), audit)
    pub, priv, pid = make_proposer()
    peer = LocalPeer(*generate_keypair_with_id("peer-1"))

    out = flow.propose_and_run(
        a,
        priv,
        pub,
        pid,
        peers=[peer],
        fn=lambda amount: amount + 1,
        timeout_s=2.0,
        amount=9,
    )
    assert out == 10
    assert audit.entries[-1]["accepted"] is True


# ---------- MerkleHTTPAuditSink (no real network) --------------------------


def test_merkle_http_audit_sink_posts_go_compatible_body():
    """Wire shape matches the Go /v1/audit/append handler exactly."""
    fake = FakeHTTP()
    sink = MerkleHTTPAuditSink("http://example.invalid", http=fake)
    a = make_action()
    pub, priv, pid = make_proposer()
    proposer_sig = sign(a, priv)
    proposal = Proposal(
        action=a,
        proposer_id=pid,
        proposer_pub=pub,
        proposer_sig=proposer_sig,
        created_at_ms=1_700_000_000_000,
    )
    sink.record(
        proposal=proposal,
        signatures=[(pub, proposer_sig)],
        accepted=True,
        reason="",
    )
    assert fake.calls, "expected an HTTP call"
    call = fake.calls[0]
    assert call["url"].endswith("/v1/audit/append")
    assert call["method"] == "POST"
    assert call["headers"]["Content-Type"] == "application/json"

    body = call["json"]
    assert set(body.keys()) == {"action", "signature"}
    assert body["signature"] == proposer_sig.hex()

    # Action must use the canonical wire keys — notably "timestamp" (not
    # "timestamp_ms") so Go's `json:"timestamp"` tag picks it up.
    action_obj = body["action"]
    assert action_obj == {
        "schema_version": a.schema_version,
        "agent_id": a.agent_id,
        "action_type": a.action_type,
        "target": a.target,
        "timestamp": a.timestamp_ms,
        "nonce": a.nonce,
    }
    # Round-trip equality with canonical bytes proves Go can re-derive the
    # exact message that was signed.
    import json as _json

    assert _json.dumps(action_obj, sort_keys=True, separators=(",", ":")).encode() == a.canonical()


def test_merkle_http_audit_sink_skips_rejected_records():
    """Rejected proposals would 401 against the Go endpoint, so don't post."""
    fake = FakeHTTP()
    sink = MerkleHTTPAuditSink("http://example.invalid", http=fake)
    a = make_action()
    pub, priv, pid = make_proposer()
    proposal = Proposal(
        action=a,
        proposer_id=pid,
        proposer_pub=pub,
        proposer_sig=sign(a, priv),
        created_at_ms=1_700_000_000_000,
    )
    sink.record(
        proposal=proposal,
        signatures=[],
        accepted=False,
        reason="threshold_not_met",
    )
    assert fake.calls == []


def test_merkle_http_audit_sink_swallow_errors_via_flow():
    """A flaky audit sink must not break execute()."""
    fake = FakeHTTP(raise_on_call=True)
    sink = MerkleHTTPAuditSink("http://example.invalid", http=fake)
    a = make_action()
    flow = ProposalFlow(Gate({a.action_type: 1}), sink)
    pub, priv, pid = make_proposer()
    proposal = flow.propose(a, priv, pub, pid)
    sigs = [(proposal.proposer_pub, proposal.proposer_sig)]
    assert flow.execute(proposal, sigs, lambda: "ok") == "ok"


# ---------- Helpers / test doubles -----------------------------------------


def generate_keypair_with_id(agent_id: str) -> tuple[str, bytes, bytes]:
    pub, priv = generate_keypair()
    return agent_id, pub, priv


class SlowLocalPeer(LocalPeer):
    def __init__(self, agent_id: str, pub: bytes, priv: bytes, *, delay_s: float) -> None:
        super().__init__(agent_id, pub, priv)
        self._delay = delay_s

    def sign(self, proposal: Proposal) -> bytes:
        time.sleep(self._delay)
        return super().sign(proposal)


class ConstantSigPeer:
    def __init__(self, agent_id: str, pub: bytes, priv: bytes, *, sig: bytes) -> None:
        self.agent_id = agent_id
        self.public_key = pub
        self._priv = priv
        self._sig = sig

    def sign(self, proposal: Proposal) -> bytes:
        return self._sig


class RaisingPeer:
    def __init__(self, agent_id: str, pub: bytes, priv: bytes) -> None:
        self.agent_id = agent_id
        self.public_key = pub

    def sign(self, proposal: Proposal) -> bytes:
        raise RuntimeError("peer down")


class AbstainPeer:
    def __init__(self, agent_id: str, pub: bytes, priv: bytes) -> None:
        self.agent_id = agent_id
        self.public_key = pub

    def sign(self, proposal: Proposal):
        return None


class ExplodingAuditSink:
    def record(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        raise RuntimeError("disk full")


class FakeHTTP:
    def __init__(self, *, raise_on_call: bool = False) -> None:
        self.calls: list[dict] = []
        self._raise = raise_on_call
        self._lock = threading.Lock()

    def post_json(self, url: str, body: dict, *, headers: dict, timeout: float) -> int:
        with self._lock:
            self.calls.append(
                {
                    "url": url,
                    "method": "POST",
                    "headers": headers,
                    "json": body,
                    "timeout": timeout,
                }
            )
        if self._raise:
            raise OSError("network down")
        return 200


# Smoke check that AuditSink protocol is satisfied at runtime.
def test_inmemory_sink_satisfies_protocol():
    sink: AuditSink = InMemoryAuditSink()
    a = make_action()
    pub, priv, pid = make_proposer()
    proposal = Proposal(
        action=a,
        proposer_id=pid,
        proposer_pub=pub,
        proposer_sig=sign(a, priv),
        created_at_ms=1,
    )
    sink.record(proposal=proposal, signatures=[], accepted=True, reason="")
    assert sink.entries[-1]["accepted"] is True
