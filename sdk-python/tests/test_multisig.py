import pytest

from cryptoagent.action import Action
from cryptoagent.multisig import (
    BypassError,
    Gate,
    ThresholdNotMetError,
    gated,
)
from cryptoagent.signing import generate_keypair, sign


def make_action(action_type: str = "transfer_funds") -> Action:
    return Action(
        schema_version=1,
        agent_id="agent-001",
        action_type=action_type,
        target="treasury",
        timestamp_ms=1_700_000_000_000,
        nonce="0123456789abcdef0123456789abcdef",
    )


def signed_by(action: Action, n: int):
    """Return n (pub, sig) tuples from distinct freshly generated keys."""
    out = []
    for _ in range(n):
        pub, priv = generate_keypair()
        out.append((pub, sign(action, priv)))
    return out


def test_threshold_met_executes_function():
    gate = Gate({"transfer_funds": 2})
    a = make_action()
    sigs = signed_by(a, 2)
    result = gate.execute(a, sigs, lambda: "moved")
    assert result == "moved"


def test_threshold_default_used_for_unknown_action_type():
    gate = Gate({"transfer_funds": 3}, default_threshold=1)
    a = make_action(action_type="other")
    sigs = signed_by(a, 1)
    assert gate.execute(a, sigs, lambda: 42) == 42


def test_threshold_not_met_raises():
    gate = Gate({"transfer_funds": 3})
    a = make_action()
    sigs = signed_by(a, 2)
    with pytest.raises(ThresholdNotMetError):
        gate.execute(a, sigs, lambda: "moved")


def test_duplicate_signer_counts_once():
    gate = Gate({"transfer_funds": 2})
    a = make_action()
    pub, priv = generate_keypair()
    sig = sign(a, priv)
    with pytest.raises(ThresholdNotMetError):
        gate.execute(a, [(pub, sig), (pub, sig)], lambda: None)


def test_invalid_signature_does_not_count():
    gate = Gate({"transfer_funds": 2})
    a = make_action()
    good = signed_by(a, 1)
    other_pub, _ = generate_keypair()
    bad_sig = b"\x00" * 64
    with pytest.raises(ThresholdNotMetError):
        gate.execute(a, [*good, (other_pub, bad_sig)], lambda: None)


def test_gated_function_blocks_direct_call():
    gate = Gate({"transfer_funds": 1})

    @gated(gate, "transfer_funds")
    def transfer():
        return "ok"

    assert gate.bypass_count() == 0
    with pytest.raises(BypassError):
        transfer()
    assert gate.bypass_count() == 1
    assert gate.bypass_count("transfer_funds") == 1


def test_gated_function_runs_inside_execute():
    gate = Gate({"transfer_funds": 1})

    @gated(gate, "transfer_funds")
    def transfer(amount: int) -> int:
        return amount * 2

    a = make_action()
    sigs = signed_by(a, 1)
    out = gate.execute(a, sigs, transfer, 21)
    assert out == 42
    assert gate.bypass_count() == 0


def test_bypass_metrics_per_action_type():
    gate = Gate()

    @gated(gate, "alpha")
    def a_fn():
        return None

    @gated(gate, "beta")
    def b_fn():
        return None

    for _ in range(3):
        with pytest.raises(BypassError):
            a_fn()
    with pytest.raises(BypassError):
        b_fn()

    assert gate.bypass_metrics() == {"alpha": 3, "beta": 1}
    assert gate.bypass_count() == 4


def test_set_threshold_validates():
    gate = Gate()
    with pytest.raises(ValueError):
        gate.set_threshold("x", 0)


def test_evaluate_only_does_not_run_function():
    gate = Gate({"transfer_funds": 1})
    a = make_action()
    sigs = signed_by(a, 1)
    ok, valid = gate.evaluate(a, sigs)
    assert ok and len(valid) == 1


def test_nested_execute_resets_flag():
    """After execute returns, is_executing must be False even on errors."""
    gate = Gate({"x": 1})
    a = make_action(action_type="x")
    sigs = signed_by(a, 1)

    def boom():
        raise RuntimeError("inner")

    with pytest.raises(RuntimeError):
        gate.execute(a, sigs, boom)
    assert not gate.is_executing()
