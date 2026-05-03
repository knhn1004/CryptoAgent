import pytest

from cryptoagent import (
    ACL,
    CapabilityError,
    Token,
    TokenClient,
    TokenError,
    UnauthorizedMetrics,
    requires_token,
    signed_action,
    token_context,
)
from cryptoagent.signing import generate_keypair

# Re-use the in-process fake server fixture from conftest so the
# decorator path is exercised against the same wire shape Adarsh's
# TokenClient was tested with — no new HTTP scaffolding here. The
# `fake_service` fixture is auto-discovered by pytest.
from tests.conftest import _issue_response


def test_grant_and_check():
    acl = ACL()
    acl.grant("agent-a", "read")
    assert acl.has("agent-a", "read")
    assert not acl.has("agent-a", "write")


def test_initial_grants():
    acl = ACL({"agent-a": ["read", "write"]})
    assert acl.has("agent-a", "read")
    assert acl.has("agent-a", "write")


def test_require_raises():
    acl = ACL()
    with pytest.raises(CapabilityError):
        acl.require("agent-a", "read")


def test_revoke():
    acl = ACL({"agent-a": ["read"]})
    acl.revoke("agent-a", "read")
    assert not acl.has("agent-a", "read")
    # idempotent
    acl.revoke("agent-a", "read")
    acl.revoke("ghost", "read")


def test_capabilities_snapshot_is_copy():
    acl = ACL({"a": ["x"]})
    snap = acl.capabilities("a")
    snap.add("y")
    assert acl.capabilities("a") == {"x"}


# ---------------------------------------------------------------------------
# UnauthorizedMetrics — issue #17 success-metric counter
# ---------------------------------------------------------------------------


def test_metrics_record_and_count():
    m = UnauthorizedMetrics()
    m.record("transfer_funds")
    m.record("transfer_funds")
    m.record("delete")
    assert m.count("transfer_funds") == 2
    assert m.count("delete") == 1
    assert m.count() == 3


def test_metrics_snapshot_is_copy():
    m = UnauthorizedMetrics()
    m.record("transfer_funds")
    snap = m.snapshot()
    snap["transfer_funds"] = 99
    assert m.count("transfer_funds") == 1


def test_metrics_reset():
    m = UnauthorizedMetrics()
    m.record("x")
    m.reset()
    assert m.count() == 0


# ---------------------------------------------------------------------------
# Decorator integration: server-side rejection bumps the local counter.
# Covers the issue #17 acceptance bullets end-to-end against the real
# TokenClient with a stubbed HTTP backend (no network).
# ---------------------------------------------------------------------------


def _wrap(client: TokenClient, metrics: UnauthorizedMetrics, *, target: str = "acct:1"):
    _, priv = generate_keypair()

    @signed_action(
        agent_id="agent-a",
        action_type="transfer",
        target=target,
        private_key=priv,
        clock=lambda: 1_700_000_000_000,
    )
    @requires_token(client, action_type="transfer", target=target, metrics=metrics)
    def call() -> str:
        return "ran"

    return call


def test_in_scope_allowed_no_metric_increment(fake_service):
    svc, base = fake_service
    svc.queue(200, {"ok": True, "token_id": "tok-1"})
    client = TokenClient(base)
    metrics = UnauthorizedMetrics()
    call = _wrap(client, metrics)
    with token_context(Token.from_response(_issue_response())):
        assert call() == "ran"
    assert metrics.count() == 0


def test_out_of_scope_action_type_rejected_and_counted(fake_service):
    svc, base = fake_service
    svc.queue(403, {"error": "action_type_not_allowed", "message": "nope"})
    client = TokenClient(base)
    metrics = UnauthorizedMetrics()
    call = _wrap(client, metrics)
    with token_context(Token.from_response(_issue_response())):
        with pytest.raises(TokenError):
            call()
    assert metrics.count("transfer") == 1
    assert metrics.count() == 1


def test_out_of_scope_target_rejected_and_counted(fake_service):
    svc, base = fake_service
    svc.queue(403, {"error": "target_not_allowed", "message": "nope"})
    client = TokenClient(base)
    metrics = UnauthorizedMetrics()
    call = _wrap(client, metrics)
    with token_context(Token.from_response(_issue_response())):
        with pytest.raises(TokenError):
            call()
    assert metrics.count("transfer") == 1


def test_expired_rejected_and_counted(fake_service):
    svc, base = fake_service
    svc.queue(403, {"error": "expired", "message": "expired"})
    client = TokenClient(base)
    metrics = UnauthorizedMetrics()
    call = _wrap(client, metrics)
    with token_context(Token.from_response(_issue_response())):
        with pytest.raises(TokenError) as exc:
            call()
    assert exc.value.error_code == "expired"
    assert metrics.count("transfer") == 1


def test_revoked_rejected_and_counted(fake_service):
    svc, base = fake_service
    svc.queue(403, {"error": "revoked", "message": "revoked"})
    client = TokenClient(base)
    metrics = UnauthorizedMetrics()
    call = _wrap(client, metrics)
    with token_context(Token.from_response(_issue_response())):
        with pytest.raises(TokenError):
            call()
    assert metrics.count("transfer") == 1


def test_missing_token_context_counted(fake_service):
    _, base = fake_service
    client = TokenClient(base)
    metrics = UnauthorizedMetrics()
    call = _wrap(client, metrics)
    # No token_context() — the decorator must reject and count.
    with pytest.raises(TokenError):
        call()
    assert metrics.count("transfer") == 1


def test_metrics_optional_decorator_works_without_it(fake_service):
    svc, base = fake_service
    svc.queue(403, {"error": "expired", "message": "expired"})
    client = TokenClient(base)
    _, priv = generate_keypair()

    @signed_action(
        agent_id="agent-a",
        action_type="transfer",
        target="acct:1",
        private_key=priv,
        clock=lambda: 1_700_000_000_000,
    )
    @requires_token(client, action_type="transfer", target="acct:1")
    def call() -> str:
        return "ran"

    with token_context(Token.from_response(_issue_response())):
        with pytest.raises(TokenError):
            call()
