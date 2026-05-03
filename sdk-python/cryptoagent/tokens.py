"""Scoped capability tokens issued by the Go key-service.

A :class:`Token` is opaque-ish JSON returned by the service plus a
detached Ed25519 signature. The SDK never verifies the signature itself;
verification is server-authoritative via :meth:`TokenClient.verify`. The
SDK keeps the original ``claims_json`` bytes so every verify call sends
back exactly what the service signed (avoids canonicalization drift).

Decorators that gate an action on a token live in :mod:`.decorators`.
"""

from __future__ import annotations

import contextlib
import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any


class TokenError(PermissionError):
    """Service refused a token operation, or the SDK could not produce
    one. Subclasses :class:`PermissionError` so the existing decorator
    stack handles it like :class:`~cryptoagent.acl.CapabilityError`.

    ``error_code`` is the service's machine code (e.g. ``"expired"``,
    ``"revoked"``) for server-originated errors, or ``None`` for
    client-side errors (missing context, etc.).
    """

    def __init__(self, message: str, *, error_code: str | None = None) -> None:
        super().__init__(message)
        self.error_code = error_code


class TokenServiceUnavailableError(TokenError):
    """Service unreachable, timed out, or returned 5xx. Fail-closed: the
    decorator denies the action."""


@dataclass(frozen=True)
class Token:
    """A capability token returned by the service.

    ``claims_json`` is the exact byte string the service signed; never
    re-marshal it. The remaining fields are convenience accessors parsed
    from ``claims_json`` for filtering/logging — they are *not*
    authoritative.
    """

    claims_json: str
    signature_hex: str
    token_id: str
    agent_id: str
    expires_at: int

    @classmethod
    def from_response(cls, body: dict[str, Any]) -> Token:
        claims_json = body["claims_json"]
        sig_hex = body["signature_hex"]
        claims = json.loads(claims_json)
        return cls(
            claims_json=claims_json,
            signature_hex=sig_hex,
            token_id=body.get("token_id") or claims["token_id"],
            agent_id=claims["agent_id"],
            expires_at=int(claims["expires_at"]),
        )


_context = threading.local()


def current_token() -> Token | None:
    """Return the active token in this thread, or ``None``."""
    stack = getattr(_context, "stack", None)
    if not stack:
        return None
    return stack[-1]


def set_token(token: Token) -> None:
    """Push ``token`` onto the active stack. Call :func:`clear_token`
    when done."""
    stack = getattr(_context, "stack", None)
    if stack is None:
        stack = []
        _context.stack = stack
    stack.append(token)


def clear_token() -> None:
    """Pop the most recent token. No-op if the stack is empty."""
    stack = getattr(_context, "stack", None)
    if stack:
        stack.pop()


@contextlib.contextmanager
def token_context(token: Token) -> Iterator[Token]:
    """Bind ``token`` as the active token for the duration of the
    ``with`` block."""
    set_token(token)
    try:
        yield token
    finally:
        clear_token()


class _UrllibClient:
    """Default HTTP client. Stdlib only — same approach as
    :class:`~cryptoagent.proposal._UrllibPoster`."""

    def request(
        self,
        method: str,
        url: str,
        *,
        body: dict[str, Any] | None,
        timeout: float,
    ) -> tuple[int, bytes]:
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — caller-owned URL
                return int(resp.status), resp.read()
        except urllib.error.HTTPError as e:
            return int(e.code), e.read() or b""


class TokenClient:
    """Client for the Go service's ``/v1/tokens`` endpoints.

    All methods raise :class:`TokenError` (or
    :class:`TokenServiceUnavailableError`) on failure. The client is
    thread-safe to share if the underlying ``http`` client is.
    """

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 5.0,
        http: Any = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._http = http or _UrllibClient()

    def issue(
        self,
        agent_id: str,
        action_types: Iterable[str],
        targets: Iterable[str],
        ttl_seconds: int,
    ) -> Token:
        body = {
            "agent_id": agent_id,
            "action_types": list(action_types),
            "targets": list(targets),
            "ttl_seconds": int(ttl_seconds),
        }
        status, payload = self._do("POST", "/v1/tokens", body)
        if status != 201:
            raise self._error_from(status, payload)
        return Token.from_response(json.loads(payload))

    def verify(
        self,
        token: Token,
        *,
        action_type: str,
        target: str,
        agent_id: str,
    ) -> None:
        body = {
            "claims_json": token.claims_json,
            "signature_hex": token.signature_hex,
            "agent_id": agent_id,
            "action_type": action_type,
            "target": target,
        }
        status, payload = self._do("POST", "/v1/tokens/verify", body)
        if status != 200:
            raise self._error_from(status, payload)

    def revoke(self, token_id: str) -> None:
        status, payload = self._do("POST", f"/v1/tokens/{token_id}/revoke", None)
        if status != 204:
            raise self._error_from(status, payload)

    def _do(
        self, method: str, path: str, body: dict[str, Any] | None
    ) -> tuple[int, bytes]:
        try:
            return self._http.request(
                method, self._base + path, body=body, timeout=self._timeout
            )
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise TokenServiceUnavailableError(
                f"token service unreachable: {e}"
            ) from e

    @staticmethod
    def _error_from(status: int, payload: bytes) -> TokenError:
        code: str | None = None
        message = f"HTTP {status}"
        try:
            envelope = json.loads(payload) if payload else {}
        except json.JSONDecodeError:
            envelope = {}
        if isinstance(envelope, dict):
            code = envelope.get("error") or None
            if envelope.get("message"):
                message = envelope["message"]
        if status >= 500:
            return TokenServiceUnavailableError(message, error_code=code)
        return TokenError(message, error_code=code)
