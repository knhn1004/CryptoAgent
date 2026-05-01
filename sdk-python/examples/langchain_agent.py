"""End-to-end example: a LangChain Tool fully wrapped with the
CryptoAgent trust layer.

Each call to the tool:

  1. Builds a canonical :class:`Action` for the agent.
  2. Signs it with the agent's Ed25519 private key.
  3. Verifies the agent has the right capability via :class:`ACL`.
  4. Routes the call through a :class:`Gate` enforcing 2-of-N approval.

Run::

    pip install -e ".[langchain]"
    python examples/langchain_agent.py
"""

from __future__ import annotations

from cryptoagent import ACL, Action, Gate, generate_keypair, sign
from cryptoagent.langchain_integration import signed_tool


def main() -> None:
    # 1. Mint keys for three agents.
    alice_pub, alice_priv = generate_keypair()
    bob_pub, bob_priv = generate_keypair()
    carol_pub, carol_priv = generate_keypair()

    # 2. ACL: Alice may transfer; Bob and Carol are co-approvers only.
    acl = ACL({"alice": ["transfer_funds"]})

    # 3. Gate: 2-of-3 required for transfer_funds.
    gate = Gate({"transfer_funds": 2})

    # 4. Build a LangChain Tool wrapped end-to-end.
    def transfer(amount: int, *, agent_id: str = "alice") -> str:
        return f"transferred {amount} units to treasury"

    tool = signed_tool(
        name="transfer_funds",
        description="Transfer funds from the agent's account to the treasury.",
        func=transfer,
        agent_id="alice",
        private_key=alice_priv,
        target="treasury",
        acl=acl,
        capability="transfer_funds",
        gate=gate,
        threshold=2,
    )

    # 5. Co-approvers sign the same canonical action.
    proposed = Action(
        schema_version=1,
        agent_id="alice",
        action_type="transfer_funds",
        target="treasury",
        timestamp_ms=1_700_000_000_000,
        nonce="0123456789abcdef0123456789abcdef",
    )
    signatures = [
        (bob_pub, sign(proposed, bob_priv)),
        (carol_pub, sign(proposed, carol_priv)),
    ]
    _ = alice_pub  # Alice's signature is generated internally by signed_action.

    # 6. Drive the tool through the gate.
    print(
        gate.execute(
            proposed,
            signatures,
            tool.func,
            10,
            agent_id="alice",
        )
    )
    print("bypass attempts so far:", gate.bypass_metrics())


if __name__ == "__main__":
    main()
