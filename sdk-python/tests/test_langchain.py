import pytest

from cryptoagent import ACL, Action, Gate, generate_keypair, sign

langchain_core = pytest.importorskip("langchain_core")

from cryptoagent.langchain_integration import signed_tool  # noqa: E402


def test_signed_tool_invocation_through_gate():
    alice_pub, alice_priv = generate_keypair()
    bob_pub, bob_priv = generate_keypair()

    acl = ACL({"alice": ["transfer"]})
    gate = Gate({"transfer": 2})

    def transfer(amount: int, *, agent_id: str = "alice") -> str:
        return f"moved {amount}"

    tool = signed_tool(
        name="transfer",
        description="move funds",
        func=transfer,
        agent_id="alice",
        private_key=alice_priv,
        acl=acl,
        capability="transfer",
        gate=gate,
        threshold=2,
    )

    a = Action(
        schema_version=1,
        agent_id="alice",
        action_type="transfer",
        target="transfer",
        timestamp_ms=1,
        nonce="0" * 32,
    )
    sigs = [(alice_pub, sign(a, alice_priv)), (bob_pub, sign(a, bob_priv))]

    out = gate.execute(a, sigs, tool.func, 7, agent_id="alice")
    assert out == "moved 7"
