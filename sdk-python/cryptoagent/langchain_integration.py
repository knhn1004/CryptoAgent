"""LangChain integration: wrap a Tool so every invocation is signed.

Optional. ``pip install "cryptoagent[langchain]"`` brings in the
LangChain dependency; without it, importing this module raises a clear
error at construction time, not import time, so the rest of the SDK
remains usable.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .acl import ACL
from .decorators import requires_capability, signed_action
from .multisig import Gate, gated

try:
    from langchain_core.tools import StructuredTool, Tool

    _LANGCHAIN_AVAILABLE = True
    _LANGCHAIN_IMPORT_ERROR: Exception | None = None
except Exception as e:  # pragma: no cover - import-time only
    StructuredTool = None  # type: ignore[assignment]
    Tool = None  # type: ignore[assignment]
    _LANGCHAIN_AVAILABLE = False
    _LANGCHAIN_IMPORT_ERROR = e


def _require_langchain() -> None:
    if not _LANGCHAIN_AVAILABLE:
        raise ImportError(
            "langchain-core is required for cryptoagent.langchain_integration; "
            "install with `pip install 'cryptoagent[langchain]'`."
        ) from _LANGCHAIN_IMPORT_ERROR


def signed_tool(
    *,
    name: str,
    description: str,
    func: Callable[..., Any],
    agent_id: str,
    private_key: bytes,
    target: str | Callable[..., str] | None = None,
    acl: ACL | None = None,
    capability: str | None = None,
    gate: Gate | None = None,
    threshold: int | None = None,
):
    """Build a LangChain ``Tool`` whose underlying function is wrapped
    with ``@signed_action`` (and optionally ``@requires_capability`` and
    a ``@gated`` invariant). Callers drive the tool via
    ``gate.execute(action, signatures, tool.func, *args, **kwargs)``.

    ``target`` defaults to the tool ``name`` if not supplied.
    """
    _require_langchain()

    action_type = name
    target_arg = target if target is not None else name

    wrapped = signed_action(
        agent_id=agent_id,
        action_type=action_type,
        target=target_arg,
        private_key=private_key,
    )(func)

    if acl is not None and capability is not None:
        wrapped = requires_capability(acl, capability)(wrapped)

    if gate is not None:
        if threshold is not None:
            gate.set_threshold(action_type, threshold)
        wrapped = gated(gate, action_type)(wrapped)

    return Tool.from_function(
        func=wrapped,
        name=name,
        description=description,
    )


__all__ = ["signed_tool"]
