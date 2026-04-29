"""Canonical agent action message.

Mirror of go-key-service/internal/action/action.go. See docs/schema.md
for the contract; both libraries MUST produce byte-identical canonical
encodings for equal inputs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

SCHEMA_VERSION = 1
NONCE_HEX_LEN = 32
MAX_SKEW_MS = 30_000
NONCE_WINDOW_MS = 600_000

_HEX_LOWER = set("0123456789abcdef")


class ActionError(ValueError):
    """Base class for action validation errors."""


@dataclass(frozen=True)
class Action:
    schema_version: int
    agent_id: str
    action_type: str
    target: str
    timestamp_ms: int
    nonce: str

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ActionError(
                f"unsupported schema_version: got {self.schema_version} want {SCHEMA_VERSION}"
            )
        if not self.agent_id or not self.action_type or not self.target:
            raise ActionError("required field empty")
        if len(self.nonce) != NONCE_HEX_LEN or any(c not in _HEX_LOWER for c in self.nonce):
            raise ActionError("nonce must be 32 lowercase hex chars")
        if not isinstance(self.timestamp_ms, int) or isinstance(self.timestamp_ms, bool):
            raise ActionError("timestamp must be int milliseconds")

    def canonical(self) -> bytes:
        """Deterministic JSON bytes used for signing and hashing."""
        self.validate()
        payload = {
            "action_type": self.action_type,
            "agent_id": self.agent_id,
            "nonce": self.nonce,
            "schema_version": self.schema_version,
            "target": self.target,
            "timestamp": self.timestamp_ms,
        }
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
