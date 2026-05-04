"""End-to-end success-metric tests for the orchestrator side.

The proposal lists four numeric success metrics. This file covers the
two that live on the SDK side; the other two (signature verification
rate, tamper detection) are exercised in
``go-key-service/internal/e2e``.

Metrics covered here:

* **Multi-sig bypass count** — a critical action wrapped in ``@gated``
  must increment ``Gate.bypass_count`` when a caller skips
  ``Gate.execute``. This is the success-metric input for "how often
  did the trust layer block an end-run around the multi-sig gate?".
* **Out-of-scope action rejection count** — a call wrapped in
  ``@requires_token`` whose token does not cover
  ``(action_type, target)`` must be rejected by the Go service's
  ``/v1/tokens/verify`` endpoint, and the orchestrator's
  ``UnauthorizedMetrics`` must record one increment per rejection.
"""

from __future__ import annotations

import pytest

from cryptoagent import (
    BypassError,
    Gate,
    Token,
    TokenClient,
    TokenError,
    UnauthorizedMetrics,
    gated,
    generate_keypair,
    requires_token,
    sign,
    signed_action,
    token_context,
)
from cryptoagent.action import Action
from tests.conftest import _issue_response

# ---------------------------------------------------------------------------
# Metric 2 — multi-sig bypass count
# ---------------------------------------------------------------------------


def _critical_action(*, agent_id: str = "alice", target: str = "vault/treasury") -> Action:
    return Action(
        schema_version=1,
        agent_id=agent_id,
        action_type="transfer_funds",
        target=target,
        timestamp_ms=1_700_000_000_000,
        nonce="0123456789abcdef0123456789abcdef",
    )


def test_metric_bypass_attempt_is_rejected_and_counted():
    gate = Gate({"transfer_funds": 2})

    @gated(gate, "transfer_funds")
    def transfer(amount: int) -> str:
        return f"moved {amount}"

    # Direct invocation outside Gate.execute is the bypass scenario.
    with pytest.raises(BypassError):
        transfer(10)

    # And one rejection records exactly one increment, attributed to
    # the action_type the dashboard groups by.
    assert gate.bypass_count("transfer_funds") == 1
    assert gate.bypass_count() == 1
    assert gate.bypass_metrics() == {"transfer_funds": 1}


def test_metric_bypass_only_counts_actual_bypass_not_normal_use():
    # Build a 2-of-2 quorum: two valid signers must both sign.
    a_pub, a_priv = generate_keypair()
    b_pub, b_priv = generate_keypair()
    gate = Gate({"transfer_funds": 2})

    @gated(gate, "transfer_funds")
    def transfer(amount: int) -> str:
        return f"moved {amount}"

    a = _critical_action()
    sig_a = sign(a, a_priv)
    sig_b = sign(a, b_priv)

    # Going through Gate.execute is the legitimate path. No increment.
    out = gate.execute(a, [(a_pub, sig_a), (b_pub, sig_b)], transfer, 10)
    assert out == "moved 10"
    assert gate.bypass_count() == 0

    # Now the adversary calls the wrapped function directly.
    with pytest.raises(BypassError):
        transfer(10)
    assert gate.bypass_count() == 1


# ---------------------------------------------------------------------------
# Metric 4 — out-of-scope action ACL rejection count
# ---------------------------------------------------------------------------


def _build_decorated(
    client: TokenClient, metrics: UnauthorizedMetrics, *, target: str = "vault/treasury"
):
    """Returns a callable that runs through @signed_action +
    @requires_token, sharing the same UnauthorizedMetrics so callers
    can assert the post-rejection count."""
    _, priv = generate_keypair()

    @signed_action(
        agent_id="alice",
        action_type="transfer_funds",
        target=target,
        private_key=priv,
        clock=lambda: 1_700_000_000_000,
    )
    @requires_token(
        client,
        action_type="transfer_funds",
        target=target,
        metrics=metrics,
    )
    def call() -> str:
        return "ok"

    return call


def test_metric_out_of_scope_action_is_rejected_and_counted(fake_service):
    svc, base = fake_service
    # The Go service rejects with one of the documented sentinels;
    # the dashboard groups by the orchestrator's action_type label, so
    # which sentinel doesn't matter for the metric.
    svc.queue(403, {"error": "action_type_not_allowed", "message": "scope mismatch"})

    client = TokenClient(base)
    metrics = UnauthorizedMetrics()
    call = _build_decorated(client, metrics)

    with token_context(Token.from_response(_issue_response())):
        with pytest.raises(TokenError):
            call()

    assert metrics.count("transfer_funds") == 1
    assert metrics.count() == 1
    assert metrics.snapshot() == {"transfer_funds": 1}


def test_metric_out_of_scope_target_is_rejected_and_counted(fake_service):
    svc, base = fake_service
    svc.queue(403, {"error": "target_not_allowed", "message": "scope mismatch"})

    client = TokenClient(base)
    metrics = UnauthorizedMetrics()
    call = _build_decorated(client, metrics, target="vault/payroll")

    with token_context(Token.from_response(_issue_response())):
        with pytest.raises(TokenError):
            call()

    assert metrics.count("transfer_funds") == 1


def test_metric_in_scope_call_does_not_increment(fake_service):
    svc, base = fake_service
    svc.queue(200, {"ok": True, "token_id": "tok-1"})

    client = TokenClient(base)
    metrics = UnauthorizedMetrics()
    call = _build_decorated(client, metrics)

    with token_context(Token.from_response(_issue_response())):
        assert call() == "ok"
    # Honest path must leave the counter at zero so the dashboard's
    # unauthorized-rate isn't poisoned by every successful call.
    assert metrics.count() == 0


# ---------------------------------------------------------------------------
# Composite roll-up — emits the same shape the dashboard would render.
# ---------------------------------------------------------------------------


def test_metric_rollup_emits_dashboard_payload(fake_service):
    """Drive a small mixed workload and assert the per-metric counters
    line up with what the dashboard expects to display.
    """
    svc, base = fake_service
    # 3 honest + 2 ACL rejections + 1 bypass attempt.
    for _ in range(3):
        svc.queue(200, {"ok": True, "token_id": "tok-1"})
    for _ in range(2):
        svc.queue(403, {"error": "action_type_not_allowed", "message": "scope"})

    client = TokenClient(base)
    metrics = UnauthorizedMetrics()
    call = _build_decorated(client, metrics)
    gate = Gate({"transfer_funds": 1})

    @gated(gate, "transfer_funds")
    def transfer(amount: int) -> str:
        return f"moved {amount}"

    with token_context(Token.from_response(_issue_response())):
        for _ in range(3):
            assert call() == "ok"
        for _ in range(2):
            with pytest.raises(TokenError):
                call()

    with pytest.raises(BypassError):
        transfer(10)

    rollup = {
        "unauthorized_total": metrics.count(),
        "unauthorized_per_action": metrics.snapshot(),
        "bypass_total": gate.bypass_count(),
        "bypass_per_action": gate.bypass_metrics(),
    }
    assert rollup == {
        "unauthorized_total": 2,
        "unauthorized_per_action": {"transfer_funds": 2},
        "bypass_total": 1,
        "bypass_per_action": {"transfer_funds": 1},
    }
