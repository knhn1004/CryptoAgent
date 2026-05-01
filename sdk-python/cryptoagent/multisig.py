"""t-of-n threshold gate for critical agent actions.

A :class:`Gate` is the single point that authorizes an action: callers
collect signatures from agents, hand them to ``gate.execute(action,
sigs, fn)``, and the gate verifies each signature, counts unique valid
signers, and only invokes ``fn`` if the count meets the per-action-type
threshold.

Functions decorated with :func:`gated` raise :class:`BypassError` and
increment a metric if they are called outside ``gate.execute`` — that
is how an attempt to skip the gate is detected.
"""

from __future__ import annotations

import functools
import logging
import threading
from collections import Counter
from collections.abc import Callable, Iterable

from .action import Action
from .signing import SignatureError, verify

DEFAULT_THRESHOLD = 1


class BypassError(PermissionError):
    """A gated action was invoked without going through Gate.execute."""


class ThresholdNotMetError(PermissionError):
    """Insufficient valid distinct signers for the action type."""


class Gate:
    """t-of-n threshold gate.

    ``thresholds`` maps action_type -> required number of distinct valid
    signers. Action types absent from the map use ``default_threshold``.
    """

    def __init__(
        self,
        thresholds: dict[str, int] | None = None,
        default_threshold: int = DEFAULT_THRESHOLD,
        logger: logging.Logger | None = None,
    ) -> None:
        self._thresholds: dict[str, int] = dict(thresholds or {})
        self._default = default_threshold
        self._bypass = Counter()
        self._logger = logger or logging.getLogger("cryptoagent.multisig")
        self._exec = threading.local()

    def threshold_for(self, action_type: str) -> int:
        return self._thresholds.get(action_type, self._default)

    def set_threshold(self, action_type: str, n: int) -> None:
        if n < 1:
            raise ValueError("threshold must be >= 1")
        self._thresholds[action_type] = n

    def evaluate(
        self,
        action: Action,
        signatures: Iterable[tuple[bytes, bytes]],
    ) -> tuple[bool, set[bytes]]:
        """Return ``(ok, valid_signers)``.

        ``signatures`` is an iterable of ``(public_key, signature)``. A
        single agent contributing the same public key twice only counts
        once. ``ok`` is True iff ``len(valid_signers) >=
        threshold_for(action.action_type)``.
        """
        valid: set[bytes] = set()
        for pub, sig in signatures:
            try:
                verify(action, sig, pub)
            except (SignatureError, ValueError):
                continue
            valid.add(bytes(pub))
        ok = len(valid) >= self.threshold_for(action.action_type)
        return ok, valid

    def execute(
        self,
        action: Action,
        signatures: Iterable[tuple[bytes, bytes]],
        fn: Callable,
        *args,
        **kwargs,
    ):
        ok, valid = self.evaluate(action, signatures)
        if not ok:
            raise ThresholdNotMetError(
                f"{action.action_type}: {len(valid)} valid signers, "
                f"threshold {self.threshold_for(action.action_type)}"
            )
        prev = getattr(self._exec, "depth", 0)
        self._exec.depth = prev + 1
        try:
            return fn(*args, **kwargs)
        finally:
            self._exec.depth = prev

    def is_executing(self) -> bool:
        return getattr(self._exec, "depth", 0) > 0

    def report_bypass(self, action_type: str, reason: str = "") -> None:
        self._bypass[action_type] += 1
        self._logger.warning(
            "gate bypass attempt",
            extra={
                "action_type": action_type,
                "reason": reason,
                "count": self._bypass[action_type],
            },
        )

    def bypass_count(self, action_type: str | None = None) -> int:
        if action_type is None:
            return sum(self._bypass.values())
        return int(self._bypass[action_type])

    def bypass_metrics(self) -> dict[str, int]:
        """Snapshot of per-action-type bypass counts (for the metric report)."""
        return dict(self._bypass)


def gated(gate: Gate, action_type: str) -> Callable:
    """Wrap ``fn`` so that direct invocation outside ``gate.execute``
    raises :class:`BypassError` and increments the bypass metric."""

    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not gate.is_executing():
                gate.report_bypass(action_type, reason=f"direct call to {fn.__qualname__}")
                raise BypassError(
                    f"{action_type}: must be invoked via Gate.execute"
                )
            return fn(*args, **kwargs)

        wrapper.__cryptoagent_gated__ = (gate, action_type)  # type: ignore[attr-defined]
        return wrapper

    return deco
