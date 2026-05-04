"""Capability-based access control for agents.

Two pieces ship in this module:

* :class:`ACL` — the original simple capability-string check used by
  :func:`cryptoagent.decorators.requires_capability`. An agent either
  has a capability string or it doesn't.
* :class:`UnauthorizedMetrics` — per-action-type counter the
  orchestrator hands to :func:`cryptoagent.decorators.requires_token`.
  Server-side scope/expiry/revocation enforcement lives in
  :mod:`cryptoagent.tokens` (issued and verified by the Go service);
  this counter is the success-metric input the proposal calls for, so
  the dashboard can read "out-of-scope action rejections per type".
"""

from __future__ import annotations

import threading
from collections import Counter
from collections.abc import Iterable


class CapabilityError(PermissionError):
    """An agent invoked an action they don't have the capability for."""


class ACL:
    def __init__(self, grants: dict[str, Iterable[str]] | None = None) -> None:
        self._caps: dict[str, set[str]] = {}
        if grants:
            for agent_id, caps in grants.items():
                self._caps[agent_id] = set(caps)

    def grant(self, agent_id: str, capability: str) -> None:
        self._caps.setdefault(agent_id, set()).add(capability)

    def revoke(self, agent_id: str, capability: str) -> None:
        if agent_id in self._caps:
            self._caps[agent_id].discard(capability)

    def has(self, agent_id: str, capability: str) -> bool:
        return capability in self._caps.get(agent_id, ())

    def require(self, agent_id: str, capability: str) -> None:
        if not self.has(agent_id, capability):
            raise CapabilityError(f"agent {agent_id!r} lacks capability {capability!r}")

    def capabilities(self, agent_id: str) -> set[str]:
        return set(self._caps.get(agent_id, ()))


class UnauthorizedMetrics:
    """Per-action-type counter of rejected token verifications.

    Wired into :func:`cryptoagent.decorators.requires_token` via the
    ``metrics`` kwarg. Every rejection — server-issued ``TokenError``
    (expired, revoked, agent_mismatch, action_type_not_allowed,
    target_not_allowed, malformed, invalid_signature) and
    client-side ``TokenError`` (missing context, unreachable
    service) — increments the counter for the decorator's
    ``action_type``. The decorator's authoritative decision (raise) is
    independent of the counter; metrics never alter the outcome.

    Thread-safe: the underlying ``Counter`` is mutated under a single
    lock so the dashboard can read snapshots concurrently with active
    agent traffic.
    """

    def __init__(self) -> None:
        self._counts: Counter = Counter()
        self._lock = threading.Lock()

    def record(self, action_type: str) -> None:
        with self._lock:
            self._counts[action_type] += 1

    def count(self, action_type: str | None = None) -> int:
        with self._lock:
            if action_type is None:
                return sum(self._counts.values())
            return int(self._counts[action_type])

    def snapshot(self) -> dict[str, int]:
        """Return a copy of the per-action-type counts."""
        with self._lock:
            return dict(self._counts)

    def reset(self) -> None:
        with self._lock:
            self._counts.clear()
