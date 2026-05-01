import pytest

from cryptoagent.acl import ACL, CapabilityError
from cryptoagent.action import Action
from cryptoagent.decorators import (
    current_signed_action,
    multi_sig,
    requires_capability,
    signed_action,
)
from cryptoagent.multisig import BypassError, Gate, ThresholdNotMetError, gated
from cryptoagent.signing import generate_keypair, sign, verify


def test_signed_action_signs_and_publishes_context():
    pub, priv = generate_keypair()

    @signed_action(
        agent_id="agent-a",
        action_type="read_secret",
        target="vault/abc",
        private_key=priv,
    )
    def read_secret(name: str) -> str:
        ctx = current_signed_action()
        assert ctx is not None
        action, signature = ctx
        verify(action, signature, pub)
        assert action.agent_id == "agent-a"
        assert action.action_type == "read_secret"
        assert action.target == "vault/abc"
        return f"secret:{name}"

    assert read_secret("token") == "secret:token"
    # Outside the call, context is cleared.
    assert current_signed_action() is None


def test_signed_action_target_callable():
    _, priv = generate_keypair()

    @signed_action(
        agent_id="a",
        action_type="t",
        target=lambda args, kwargs: kwargs["resource"],
        private_key=priv,
    )
    def fn(*, resource: str) -> str:
        ctx = current_signed_action()
        assert ctx is not None
        return ctx[0].target

    assert fn(resource="db/users") == "db/users"


def test_requires_capability_blocks_missing():
    acl = ACL({"agent-a": ["read"]})

    @requires_capability(acl, "write")
    def w(*, agent_id: str) -> str:
        return "ok"

    with pytest.raises(CapabilityError):
        w(agent_id="agent-a")


def test_requires_capability_allows_granted():
    acl = ACL({"agent-a": ["write"]})

    @requires_capability(acl, "write")
    def w(*, agent_id: str) -> str:
        return "ok"

    assert w(agent_id="agent-a") == "ok"


def test_requires_capability_missing_kwarg_raises_typeerror():
    acl = ACL()

    @requires_capability(acl, "x")
    def f(*, agent_id: str):
        return None

    with pytest.raises(TypeError):
        f()


def test_multi_sig_routes_through_gate():
    gate = Gate()

    @multi_sig(gate, action_type="transfer", threshold=2)
    def transfer(amount: int) -> int:
        return amount

    a = Action(
        schema_version=1,
        agent_id="agent-a",
        action_type="transfer",
        target="t",
        timestamp_ms=1_700_000_000_000,
        nonce="0123456789abcdef0123456789abcdef",
    )
    sigs = []
    for _ in range(2):
        pub, priv = generate_keypair()
        sigs.append((pub, sign(a, priv)))

    assert transfer(amount=10, action=a, signatures=sigs) == 10


def test_multi_sig_action_type_mismatch():
    gate = Gate()

    @multi_sig(gate, action_type="transfer", threshold=1)
    def transfer():
        return None

    a = Action(
        schema_version=1,
        agent_id="x",
        action_type="other",
        target="t",
        timestamp_ms=1,
        nonce="0" * 32,
    )
    pub, priv = generate_keypair()
    with pytest.raises(ValueError):
        transfer(action=a, signatures=[(pub, sign(a, priv))])


def test_multi_sig_threshold_not_met():
    gate = Gate()

    @multi_sig(gate, action_type="transfer", threshold=3)
    def transfer():
        return "moved"

    a = Action(
        schema_version=1,
        agent_id="x",
        action_type="transfer",
        target="t",
        timestamp_ms=1,
        nonce="0" * 32,
    )
    pub, priv = generate_keypair()
    with pytest.raises(ThresholdNotMetError):
        transfer(action=a, signatures=[(pub, sign(a, priv))])


def test_full_stack_signed_capability_multisig():
    """signed_action + requires_capability + multi_sig composed on one call."""
    acl = ACL({"agent-a": ["transfer_funds"]})
    gate = Gate()

    pub, priv = generate_keypair()
    pub2, priv2 = generate_keypair()

    @gated(gate, "transfer_funds")
    @requires_capability(acl, "transfer_funds")
    @signed_action(
        agent_id="agent-a",
        action_type="transfer_funds",
        target="treasury",
        private_key=priv,
    )
    def move(amount: int, *, agent_id: str) -> int:
        ctx = current_signed_action()
        assert ctx is not None
        return amount

    a = Action(
        schema_version=1,
        agent_id="agent-a",
        action_type="transfer_funds",
        target="treasury",
        timestamp_ms=1,
        nonce="0" * 32,
    )
    sigs = [(pub, sign(a, priv)), (pub2, sign(a, priv2))]

    # Direct call without going through gate -> bypass.
    with pytest.raises(BypassError):
        move(10, agent_id="agent-a")
    assert gate.bypass_count("transfer_funds") == 1

    # Routed through gate -> succeeds.
    out = gate.execute(a, sigs, move, 10, agent_id="agent-a")
    assert out == 10
