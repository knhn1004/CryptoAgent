"""Shared pytest fixtures.

`fake_service` spins up a stdlib `http.server` on an ephemeral port that
records every call and replays a queued response — the same shape used
by `test_tokens.py` for the TokenClient. Lives here (not inside a test
file) so multiple test modules can pick it up via pytest's auto-discovery
without creating import cycles.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest


class _FakeService:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.responses: list[tuple[int, dict[str, Any] | None]] = []

    def queue(self, status: int, body: dict[str, Any] | None) -> None:
        self.responses.append((status, body))

    def pop(self) -> tuple[int, dict[str, Any] | None]:
        if not self.responses:
            return 200, {"ok": True}
        return self.responses.pop(0)


class _Handler(BaseHTTPRequestHandler):
    service: _FakeService  # injected by factory

    def log_message(self, *args, **kwargs) -> None:  # silence test noise
        pass

    def _read(self) -> dict[str, Any] | None:
        length = int(self.headers.get("Content-Length") or "0")
        if length == 0:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return None

    def _serve(self, method: str) -> None:
        body = self._read()
        self.service.calls.append({"method": method, "path": self.path, "body": body})
        status, payload = self.service.pop()
        self.send_response(status)
        if payload is None:
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            data = json.dumps(payload).encode("utf-8")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 — stdlib API name
        self._serve("GET")

    def do_POST(self) -> None:  # noqa: N802 — stdlib API name
        self._serve("POST")


@pytest.fixture
def fake_service() -> Iterator[tuple[_FakeService, str]]:
    svc = _FakeService()
    handler_cls = type("H", (_Handler,), {"service": svc})
    httpd = HTTPServer(("127.0.0.1", 0), handler_cls)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield svc, f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def _claims_payload(**overrides: Any) -> dict[str, Any]:
    base = {
        "token_id": "tok-1",
        "agent_id": "agent-a",
        "action_types": ["transfer"],
        "targets": ["acct:1"],
        "issued_at": 1_700_000_000,
        "expires_at": 1_700_003_600,
    }
    base.update(overrides)
    return base


def _issue_response(claims: dict[str, Any] | None = None) -> dict[str, Any]:
    claims = claims or _claims_payload()
    return {
        "token_id": claims["token_id"],
        "claims_json": json.dumps(claims),
        "signature_hex": "ab" * 64,
    }
