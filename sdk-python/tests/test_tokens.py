"""Tests for the scoped capability token client and decorator.

The TokenClient is exercised against a stdlib http.server fake — no
network, no extra deps. The fake records every call so tests can assert
the wire shape too.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cryptoagent.action import Action
from cryptoagent.decorators import requires_token, signed_action
from cryptoagent.signing import generate_keypair
from cryptoagent.tokens import (
    Token,
    TokenClient,
    TokenError,
    TokenServiceUnavailableError,
    clear_token,
    current_token,
    set_token,
    token_context,
)
from tests.conftest import _claims_payload, _issue_response

# ---------- Token dataclass ---------------------------------------------


def test_token_from_response_parses_convenience_fields():
    body = _issue_response()
    tok = Token.from_response(body)
    assert tok.token_id == "tok-1"
    assert tok.agent_id == "agent-a"
    assert tok.expires_at == 1_700_003_600
    # claims_json is preserved verbatim, never re-marshaled.
    assert tok.claims_json == body["claims_json"]


# ---------- token_context / current_token -------------------------------


def test_token_context_sets_and_clears():
    tok = Token.from_response(_issue_response())
    assert current_token() is None
    with token_context(tok):
        assert current_token() is tok
    assert current_token() is None


def test_set_and_clear_token():
    a = Token.from_response(_issue_response())
    b = Token.from_response(_issue_response(_claims_payload(token_id="tok-2")))
    set_token(a)
    set_token(b)
    assert current_token() is b
    clear_token()
    assert current_token() is a
    clear_token()
    assert current_token() is None
    # extra clear is a no-op
    clear_token()


# ---------- TokenClient happy paths -------------------------------------


def test_client_issue_happy(fake_service):
    svc, base = fake_service
    svc.queue(201, _issue_response())

    client = TokenClient(base)
    tok = client.issue("agent-a", ["transfer"], ["acct:1"], 3600)

    assert tok.agent_id == "agent-a"
    call = svc.calls[0]
    assert call["method"] == "POST"
    assert call["path"] == "/v1/tokens"
    assert call["body"] == {
        "agent_id": "agent-a",
        "action_types": ["transfer"],
        "targets": ["acct:1"],
        "ttl_seconds": 3600,
    }


def test_client_verify_happy(fake_service):
    svc, base = fake_service
    svc.queue(200, {"ok": True, "token_id": "tok-1"})

    client = TokenClient(base)
    tok = Token.from_response(_issue_response())
    client.verify(tok, action_type="transfer", target="acct:1", agent_id="agent-a")

    call = svc.calls[0]
    assert call["path"] == "/v1/tokens/verify"
    body = call["body"]
    # claims_json round-tripped exactly so the server can re-verify the
    # signature against bytes it produced.
    assert body["claims_json"] == tok.claims_json
    assert body["signature_hex"] == tok.signature_hex
    assert body["action_type"] == "transfer"
    assert body["target"] == "acct:1"
    assert body["agent_id"] == "agent-a"


def test_client_revoke_happy(fake_service):
    svc, base = fake_service
    svc.queue(204, None)

    TokenClient(base).revoke("tok-1")
    assert svc.calls[0]["path"] == "/v1/tokens/tok-1/revoke"


# ---------- TokenClient error mapping -----------------------------------


@pytest.mark.parametrize(
    "status,error_code,exc",
    [
        (400, "invalid_json", TokenError),
        (400, "malformed_token", TokenError),
        (401, "invalid_signature", TokenError),
        (403, "expired", TokenError),
        (403, "revoked", TokenError),
        (403, "agent_mismatch", TokenError),
        (403, "action_type_not_allowed", TokenError),
        (403, "target_not_allowed", TokenError),
        (404, "unknown_agent", TokenError),
        (500, "internal", TokenServiceUnavailableError),
        (502, "internal", TokenServiceUnavailableError),
    ],
)
def test_verify_error_mapping(fake_service, status, error_code, exc):
    svc, base = fake_service
    svc.queue(status, {"error": error_code, "message": "no"})

    client = TokenClient(base)
    tok = Token.from_response(_issue_response())
    with pytest.raises(exc) as info:
        client.verify(tok, action_type="x", target="y", agent_id="agent-a")
    assert info.value.error_code == error_code


def test_client_unreachable_raises_unavailable():
    # Open then immediately close a server so we know the port is free
    # and nothing will answer on it.
    s = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = s.server_address[1]
    s.server_close()

    client = TokenClient(f"http://127.0.0.1:{port}", timeout=0.5)
    tok = Token.from_response(_issue_response())
    with pytest.raises(TokenServiceUnavailableError):
        client.verify(tok, action_type="x", target="y", agent_id="agent-a")


# ---------- @requires_token decorator -----------------------------------


def _make_action_decorated(client: TokenClient, fn=None):
    _, priv = generate_keypair()

    def real(*args, **kwargs):
        return "ok"

    fn = fn or real

    @signed_action(
        agent_id="agent-a",
        action_type="transfer",
        target="acct:1",
        private_key=priv,
    )
    @requires_token(client, action_type="transfer", target="acct:1")
    def wrapped() -> str:
        return fn()

    return wrapped


def test_requires_token_happy(fake_service):
    svc, base = fake_service
    svc.queue(200, {"ok": True, "token_id": "tok-1"})

    client = TokenClient(base)
    fn = _make_action_decorated(client)

    with token_context(Token.from_response(_issue_response())):
        assert fn() == "ok"

    # The verify call carried the agent_id from the surrounding
    # @signed_action context, not a hard-coded value.
    body = svc.calls[0]["body"]
    assert body["agent_id"] == "agent-a"


def test_requires_token_no_signed_action_context(fake_service):
    _, base = fake_service
    client = TokenClient(base)

    @requires_token(client, action_type="transfer", target="acct:1")
    def naked() -> None:
        pass

    with token_context(Token.from_response(_issue_response())):
        with pytest.raises(TokenError):
            naked()


def test_requires_token_no_token_in_context(fake_service):
    _, base = fake_service
    client = TokenClient(base)

    fn = _make_action_decorated(client)
    with pytest.raises(TokenError):
        fn()  # token_context not entered


def test_requires_token_service_denies(fake_service):
    svc, base = fake_service
    svc.queue(403, {"error": "expired", "message": "expired"})

    client = TokenClient(base)
    fn = _make_action_decorated(client, fn=lambda: pytest.fail("wrapped fn should not run"))
    with token_context(Token.from_response(_issue_response())):
        with pytest.raises(TokenError) as info:
            fn()
    assert info.value.error_code == "expired"


def test_requires_token_fails_closed_on_5xx(fake_service):
    svc, base = fake_service
    svc.queue(503, {"error": "internal", "message": "down"})

    client = TokenClient(base)
    fn = _make_action_decorated(client, fn=lambda: pytest.fail("wrapped fn should not run on 5xx"))
    with token_context(Token.from_response(_issue_response())):
        with pytest.raises(TokenServiceUnavailableError):
            fn()


# ---------- Action import is just to keep the namespace honest ----------

_ = Action  # silence "unused import" if action ever stops being touched
