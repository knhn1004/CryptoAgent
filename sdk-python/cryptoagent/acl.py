"""Capability-based access control for agents.

An :class:`ACL` maps ``agent_id`` to a set of capability strings. A
capability is a short, application-defined verb (e.g. ``"transfer_funds"``,
``"read_secret"``); the trust layer never interprets the string, it only
checks membership.
"""

from __future__ import annotations

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
            raise CapabilityError(
                f"agent {agent_id!r} lacks capability {capability!r}"
            )

    def capabilities(self, agent_id: str) -> set[str]:
        return set(self._caps.get(agent_id, ()))
