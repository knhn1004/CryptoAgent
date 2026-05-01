"""Decorator surface for adopting the trust layer with minimal code change.

* :func:`signed_action` — sign every invocation and attach the signed
  action + signature to a thread-local context downstream consumers can
  read via :func:`current_signed_action`.
* :func:`requires_capability` — gate a call on an ACL membership check.
* :func:`multi_sig` — route a call through a :class:`Gate` so it is only
  executed when ``threshold`` distinct valid signers approved it.
"""

from __future__ import annotations

import functools
import os
import threading
import time
from collections.abc import Callable

from .acl import ACL
from .action import Action
from .multisig import Gate
from .signing import sign

_context = threading.local()


def current_signed_action() -> tuple[Action, bytes] | None:
    """Return the (action, signature) for the currently executing
    ``@signed_action`` call, or ``None`` if not inside one."""
    stack = getattr(_context, "stack", None)
    if not stack:
        return None
    return stack[-1]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _new_nonce() -> str:
    return os.urandom(16).hex()


def signed_action(
    *,
    agent_id: str,
    action_type: str,
    target: str | Callable[..., str],
    private_key: bytes,
    clock: Callable[[], int] = _now_ms,
    nonce_factory: Callable[[], str] = _new_nonce,
) -> Callable:
    """Sign the canonical action for every call.

    ``target`` may be a string or a callable ``(args, kwargs) -> str`` so
    callers can derive the resource id from the function's arguments.
    """

    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            resolved_target = target(args, kwargs) if callable(target) else target
            action = Action(
                schema_version=1,
                agent_id=agent_id,
                action_type=action_type,
                target=resolved_target,
                timestamp_ms=clock(),
                nonce=nonce_factory(),
            )
            signature = sign(action, private_key)

            stack = getattr(_context, "stack", None)
            if stack is None:
                stack = []
                _context.stack = stack
            stack.append((action, signature))
            try:
                return fn(*args, **kwargs)
            finally:
                stack.pop()

        wrapper.__cryptoagent_signed__ = True  # type: ignore[attr-defined]
        return wrapper

    return deco


def requires_capability(
    acl: ACL,
    capability: str,
    *,
    agent_id_arg: str = "agent_id",
) -> Callable:
    """Reject the call unless ``acl`` grants ``capability`` to the agent.

    The agent id is read from the keyword argument named ``agent_id_arg``
    (default ``"agent_id"``).
    """

    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if agent_id_arg not in kwargs:
                raise TypeError(f"@requires_capability needs kwarg {agent_id_arg!r}")
            acl.require(kwargs[agent_id_arg], capability)
            return fn(*args, **kwargs)

        return wrapper

    return deco


def multi_sig(
    gate: Gate,
    *,
    action_type: str,
    threshold: int | None = None,
    action_arg: str = "action",
    signatures_arg: str = "signatures",
) -> Callable:
    """Route the wrapped call through ``gate.execute``.

    Caller must pass the :class:`Action` as ``kwargs[action_arg]`` and an
    iterable of ``(public_key, signature)`` tuples as
    ``kwargs[signatures_arg]``. If ``threshold`` is provided, it is set
    on the gate for ``action_type``.
    """

    if threshold is not None:
        gate.set_threshold(action_type, threshold)

    def deco(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if action_arg not in kwargs:
                raise TypeError(f"@multi_sig needs kwarg {action_arg!r}")
            if signatures_arg not in kwargs:
                raise TypeError(f"@multi_sig needs kwarg {signatures_arg!r}")
            action = kwargs.pop(action_arg)
            signatures = kwargs.pop(signatures_arg)
            if action.action_type != action_type:
                raise ValueError(
                    f"action.action_type {action.action_type!r} "
                    f"!= decorator action_type {action_type!r}"
                )
            return gate.execute(action, signatures, fn, *args, **kwargs)

        return wrapper

    return deco
