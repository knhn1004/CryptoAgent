"""Proposal lifecycle for the multi-sig gate.

A proposer signs an :class:`Action`, peers co-sign the resulting
:class:`Proposal`, and a :class:`ProposalFlow` runs the gate, enforces
replay protection, and writes an audit record. The audit sink is
fire-and-forget: any exception it raises is logged and swallowed so the
authorization decision is never derailed by the audit transport.

Replay protection lives here (not in the gate) because it is tied to a
fully-executed proposal, not to a signature check. The window matches
:data:`cryptoagent.action.NONCE_WINDOW_MS` by default.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.request
from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .action import NONCE_WINDOW_MS, Action
from .multisig import Gate, ThresholdNotMetError
from .signing import SIGNATURE_LEN, SignatureError, sign, verify


class ProposalError(ValueError):
    """Proposal-level validation failure (bad sig, malformed fields)."""


# Re-export the gate's threshold error under a friendlier name. They are the
# same class so callers can ``except ThresholdNotReached`` or
# ``except ThresholdNotMetError`` interchangeably.
ThresholdNotReached = ThresholdNotMetError


class ReplayError(PermissionError):
    """Same (agent_id, nonce) was already executed within the replay window."""


@dataclass(frozen=True)
class Proposal:
    """An action plus the proposer's signature, ready for peer co-signing."""

    action: Action
    proposer_id: str
    proposer_pub: bytes
    proposer_sig: bytes
    created_at_ms: int

    def validate(self) -> None:
        try:
            self.action.validate()
        except ValueError as e:
            raise ProposalError(str(e)) from e
        if len(self.proposer_sig) != SIGNATURE_LEN:
            raise ProposalError(
                f"proposer_sig must be {SIGNATURE_LEN} bytes, got {len(self.proposer_sig)}"
            )
        try:
            verify(self.action, self.proposer_sig, self.proposer_pub)
        except (SignatureError, ValueError) as e:
            raise ProposalError(f"proposer signature invalid: {e}") from e


@runtime_checkable
class Peer(Protocol):
    """Anything with a public key that can sign a proposal (or abstain).

    Implementations should self-impose a deadline on ``sign``. The
    :class:`ProposalFlow` honours an overall ``timeout_s`` for the batch
    via thread cancellation, but a peer that blocks past that deadline
    keeps its worker thread alive until the call resolves (Python's
    :class:`~concurrent.futures.ThreadPoolExecutor` workers are not
    daemons, so a runaway peer can stall process exit). For
    network-backed peers, set a per-call timeout on the HTTP client.
    """

    agent_id: str
    public_key: bytes

    def sign(self, proposal: Proposal) -> bytes | None: ...


class LocalPeer:
    """Reference :class:`Peer` impl that holds a private seed and signs in-process."""

    def __init__(self, agent_id: str, public_key: bytes, private_key: bytes) -> None:
        self.agent_id = agent_id
        self.public_key = public_key
        self._priv = private_key

    def sign(self, proposal: Proposal) -> bytes:
        return sign(proposal.action, self._priv)


@runtime_checkable
class AuditSink(Protocol):
    """Sink for accept/reject decisions. ``record`` MUST NOT raise into the flow."""

    def record(
        self,
        *,
        proposal: Proposal,
        signatures: list[tuple[bytes, bytes]],
        accepted: bool,
        reason: str = "",
    ) -> None: ...


class InMemoryAuditSink:
    """Test-friendly sink that appends each call to ``entries``."""

    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(
        self,
        *,
        proposal: Proposal,
        signatures: list[tuple[bytes, bytes]],
        accepted: bool,
        reason: str = "",
    ) -> None:
        with self._lock:
            self.entries.append(
                {
                    "proposal": proposal,
                    "signatures": list(signatures),
                    "accepted": accepted,
                    "reason": reason,
                }
            )


class _UrllibPoster:
    """Default HTTP client for :class:`MerkleHTTPAuditSink`. Stdlib only."""

    def post_json(
        self,
        url: str,
        body: dict[str, Any],
        *,
        headers: dict[str, str],
        timeout: float,
    ) -> int:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — caller-owned URL
            return int(resp.status)


class MerkleHTTPAuditSink:
    """Posts accepted proposals to the Go service's ``/v1/audit/append`` endpoint.

    Wire shape matches the Go ``appendRequest``: ``{"action": <canonical
    action object>, "signature": "<hex>"}`` where the action uses the same
    JSON keys as ``action.canonical()`` (notably ``timestamp``, not
    ``timestamp_ms``) and ``signature`` is the proposer's signature — the
    byte string the Go pipeline verifies before appending.

    Rejected records are skipped: the Go endpoint is itself the
    verification gate and would 401 on a sig it can't verify. Callers that
    need rejected proposals to land somewhere durable should chain a
    second sink.

    The HTTP client is injectable so tests don't hit the network; the
    default uses :mod:`urllib.request` to keep the SDK dep-light. Errors
    propagate to the caller — :class:`ProposalFlow` is responsible for
    swallowing them.
    """

    def __init__(
        self,
        base_url: str,
        *,
        http: Any = None,
        path: str = "/v1/audit/append",
        timeout_s: float = 2.0,
    ) -> None:
        self._url = base_url.rstrip("/") + path
        self._http = http or _UrllibPoster()
        self._timeout = timeout_s

    def record(
        self,
        *,
        proposal: Proposal,
        signatures: list[tuple[bytes, bytes]],
        accepted: bool,
        reason: str = "",
    ) -> None:
        if not accepted:
            return
        # Round-trip through canonical() so the wire keys (notably
        # "timestamp", not "timestamp_ms") match Go's struct tags exactly.
        # action.canonical() is the single source of truth for both sides.
        action_obj = json.loads(proposal.action.canonical())
        body = {"action": action_obj, "signature": proposal.proposer_sig.hex()}
        self._http.post_json(
            self._url,
            body,
            headers={"Content-Type": "application/json"},
            timeout=self._timeout,
        )


def _now_ms() -> int:
    return int(time.time() * 1000)


class ProposalFlow:
    """Orchestrates proposal -> co-sign -> gate.execute -> audit -> result.

    Replay cache: executed ``(agent_id, nonce)`` pairs are kept for
    ``window_ms``. The cache is pruned lazily on every ``execute`` call —
    no background thread, so an idle flow never grows memory but a
    long-lived process pruning only on access is acceptable since each
    entry is ~64 bytes.
    """

    def __init__(
        self,
        gate: Gate,
        audit: AuditSink,
        *,
        window_ms: int = NONCE_WINDOW_MS,
        clock: Callable[[], int] = _now_ms,
        logger: logging.Logger | None = None,
    ) -> None:
        self._gate = gate
        self._audit = audit
        self._window = window_ms
        self._clock = clock
        self._logger = logger or logging.getLogger("cryptoagent.proposal")
        self._executed: dict[tuple[str, str], int] = {}
        self._executed_lock = threading.Lock()

    # ---- proposal construction ------------------------------------------

    def propose(
        self,
        action: Action,
        proposer_priv: bytes,
        proposer_pub: bytes,
        proposer_id: str,
    ) -> Proposal:
        sig = sign(action, proposer_priv)
        proposal = Proposal(
            action=action,
            proposer_id=proposer_id,
            proposer_pub=proposer_pub,
            proposer_sig=sig,
            created_at_ms=self._clock(),
        )
        proposal.validate()
        return proposal

    # ---- co-signing ------------------------------------------------------

    def collect_signatures(
        self,
        proposal: Proposal,
        peers: Sequence[Peer],
        *,
        timeout_s: float,
        max_workers: int = 8,
    ) -> list[tuple[bytes, bytes]]:
        """Concurrently ask each peer to sign.

        Always includes ``(proposer_pub, proposer_sig)`` first. Peers are
        deduped by ``public_key`` (last writer wins so an explicit re-sign
        replaces an earlier one — it's still valid for the same action so
        the choice is cosmetic). Peers that return ``None``, raise, return
        a wrong-length blob, or return a sig that fails verification are
        dropped with a debug log.
        """
        proposal.validate()
        results: dict[bytes, bytes] = {bytes(proposal.proposer_pub): proposal.proposer_sig}

        if not peers:
            return list(results.items())

        workers = max(1, min(max_workers, len(peers)))
        ex = ThreadPoolExecutor(max_workers=workers)
        try:
            futures = {ex.submit(self._ask_peer, peer, proposal): peer for peer in peers}
            done, not_done = wait(futures, timeout=timeout_s)
            for fut in not_done:
                peer = futures[fut]
                fut.cancel()
                self._logger.debug("peer timed out", extra={"peer": peer.agent_id})
            for fut in done:
                peer = futures[fut]
                try:
                    pub_sig = fut.result()
                except Exception as e:  # noqa: BLE001 — policy is to skip and log
                    self._logger.debug("peer raised", extra={"peer": peer.agent_id, "err": repr(e)})
                    continue
                if pub_sig is None:
                    continue
                pub, sig = pub_sig
                results[bytes(pub)] = sig
        finally:
            # Don't block on slow peers: detach the pool so still-running
            # tasks are abandoned once collect_signatures returns.
            ex.shutdown(wait=False, cancel_futures=True)

        return list(results.items())

    def _ask_peer(self, peer: Peer, proposal: Proposal) -> tuple[bytes, bytes] | None:
        try:
            sig = peer.sign(proposal)
        except Exception as e:  # noqa: BLE001 — policy is to skip and log
            self._logger.debug("peer sign raised", extra={"peer": peer.agent_id, "err": repr(e)})
            return None
        if sig is None:
            self._logger.info("peer abstained", extra={"peer": peer.agent_id})
            return None
        if not isinstance(sig, (bytes, bytearray)) or len(sig) != SIGNATURE_LEN:
            self._logger.debug("peer returned wrong-length sig", extra={"peer": peer.agent_id})
            return None
        try:
            verify(proposal.action, bytes(sig), peer.public_key)
        except (SignatureError, ValueError):
            self._logger.debug("peer returned invalid sig", extra={"peer": peer.agent_id})
            return None
        self._logger.info("peer signed", extra={"peer": peer.agent_id})
        return bytes(peer.public_key), bytes(sig)

    # ---- execution -------------------------------------------------------

    def execute(
        self,
        proposal: Proposal,
        signatures: Iterable[tuple[bytes, bytes]],
        fn: Callable,
        *args,
        **kwargs,
    ):
        proposal.validate()
        sigs_list = list(signatures)

        # Replay check first — a replay must NOT trigger the gate.
        self._prune_replay_cache()
        key = (proposal.action.agent_id, proposal.action.nonce)
        with self._executed_lock:
            seen_at = self._executed.get(key)
        if seen_at is not None:
            self._safe_record(proposal, sigs_list, accepted=False, reason="replay")
            raise ReplayError(f"action ({key[0]}, {key[1]}) already executed at {seen_at}")

        try:
            result = self._gate.execute(proposal.action, sigs_list, fn, *args, **kwargs)
        except ThresholdNotMetError:
            self._safe_record(proposal, sigs_list, accepted=False, reason="threshold_not_met")
            raise
        with self._executed_lock:
            self._executed[key] = self._clock()
        self._safe_record(proposal, sigs_list, accepted=True, reason="")
        return result

    def propose_and_run(
        self,
        action: Action,
        proposer_priv: bytes,
        proposer_pub: bytes,
        proposer_id: str,
        peers: Sequence[Peer],
        fn: Callable,
        *,
        timeout_s: float,
        **kwargs,
    ):
        proposal = self.propose(action, proposer_priv, proposer_pub, proposer_id)
        sigs = self.collect_signatures(proposal, peers, timeout_s=timeout_s)
        return self.execute(proposal, sigs, fn, **kwargs)

    # ---- internals -------------------------------------------------------

    def _safe_record(
        self,
        proposal: Proposal,
        signatures: list[tuple[bytes, bytes]],
        *,
        accepted: bool,
        reason: str,
    ) -> None:
        try:
            self._audit.record(
                proposal=proposal,
                signatures=signatures,
                accepted=accepted,
                reason=reason,
            )
        except Exception as e:  # noqa: BLE001 — never break the flow on audit failure
            self._logger.warning(
                "audit sink failed",
                extra={"err": repr(e), "accepted": accepted, "reason": reason},
            )

    def _prune_replay_cache(self) -> None:
        cutoff = self._clock() - self._window
        with self._executed_lock:
            stale = [k for k, ts in self._executed.items() if ts < cutoff]
            for k in stale:
                del self._executed[k]


__all__ = [
    "AuditSink",
    "InMemoryAuditSink",
    "LocalPeer",
    "MerkleHTTPAuditSink",
    "Peer",
    "Proposal",
    "ProposalError",
    "ProposalFlow",
    "ReplayError",
    "ThresholdNotReached",
]
