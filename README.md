# CryptoAgent

Cryptographic guardrails for multi-agent AI systems. CS 168 (Spring 2026)
project.

Every action an agent takes is signed against a canonical schema,
mirrored into a Merkle log, and (for sensitive actions) gated behind a
t-of-n approval threshold and an ACL capability check. The goal is a
Python SDK developers can drop into an existing LangChain agent with
three decorators — `@signed_action`, `@requires_capability`, and
`@multi_sig` — and get the trust layer for free.

## Layout

| Path               | Purpose                                                              |
|--------------------|----------------------------------------------------------------------|
| `go-key-service/`  | Go HTTP service: keypairs, sign/verify, Merkle root verifier.        |
| `sdk-python/`      | Python SDK + LangChain integration consumed by agent code.           |
| `dashboard/`       | React + TypeScript dashboard (Merkle tree + agent interaction view). |
| `contracts/`       | Solidity anchoring contract (Foundry) for periodic root commits.     |
| `docs/`            | Specs and design notes. See [docs/index](#further-reading) below.    |

## Quickstart

### 1. Run the key service

```sh
cd go-key-service
go test ./...                         # all packages green
go run ./cmd/keyserver                # starts on :8080

# in another shell:
curl -s localhost:8080/health
curl -s -XPOST localhost:8080/v1/keys -d '{"agent_id":"alice"}'
curl -s localhost:8080/v1/keys/alice
```

Config: `KEYSERVER_ADDR` (default `:8080`), `KEYSERVER_LOG_LEVEL`
(`debug|info|warn|error`).

### 2. Use the Python SDK

```sh
cd sdk-python
python3.11 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,langchain]"
pytest -q
```

```python
from cryptoagent import (
    ACL, Action, Gate, generate_keypair, sign,
    signed_action, requires_capability, gated,
)

acl = ACL({"alice": ["transfer_funds"]})
gate = Gate({"transfer_funds": 2})            # 2-of-N

alice_pub, alice_priv = generate_keypair()
bob_pub,   bob_priv   = generate_keypair()

@gated(gate, "transfer_funds")
@requires_capability(acl, "transfer_funds")
@signed_action(
    agent_id="alice",
    action_type="transfer_funds",
    target="treasury",
    private_key=alice_priv,
)
def transfer(amount: int, *, agent_id: str) -> str:
    return f"moved {amount}"

proposed = Action(
    schema_version=1, agent_id="alice", action_type="transfer_funds",
    target="treasury", timestamp_ms=1_700_000_000_000,
    nonce="0123456789abcdef0123456789abcdef",
)
sigs = [(alice_pub, sign(proposed, alice_priv)),
        (bob_pub,   sign(proposed, bob_priv))]

print(gate.execute(proposed, sigs, transfer, 10, agent_id="alice"))
```

A direct call to `transfer(10, agent_id="alice")` (skipping the gate)
raises `BypassError` and increments `gate.bypass_metrics()` — that is
how the success-metric report counts attempted bypass.

A full LangChain Tool example is at
[`sdk-python/examples/langchain_agent.py`](sdk-python/examples/langchain_agent.py).

### 3. Verify a historical Merkle root

```sh
cd go-key-service
# leaves.hex: newline-delimited hex of leaf payloads (canonical(action) || sig)
go run ./cmd/merkle-verify \
  --historical-root <hex> --historical-size 32 --leaves-file leaves.hex
```

Exit 0 = consistent. Exit 1 = divergence; stderr carries a hex-bearing
diagnostic (`derived old root <hex> != <hex>`).

## Phases

1. **Core crypto infra** — key service, sign/verify, canonical schema (epic #1, ✅)
2. **Merkle audit log + on-chain anchoring** — RFC 6962 tree + root verifier (epic #2, partial)
3. **Multi-sig consensus, ACL, Python SDK** — gate, ACL, decorators, LangChain wrapper (epic #3, ✅)
4. **Dashboard + demo** — agent interaction view + Merkle tree viz (epic #4, in progress)

## Local checks

```sh
( cd go-key-service && go test ./... )
( cd sdk-python && pytest -q && ruff check . )
pre-commit run --all-files                  # one-time: pip install pre-commit && pre-commit install
```

CI mirrors these on every PR (see `.github/workflows/`).

## Further reading

- [`docs/schema.md`](docs/schema.md) — canonical action schema and replay rules.
- [`docs/architecture.md`](docs/architecture.md) — component diagram, data flow, deployment notes.
- [`docs/sdk.md`](docs/sdk.md) — full SDK usage guide with the LangChain example.
- [`docs/threat_model.md`](docs/threat_model.md) — threats addressed, non-goals, residual risks.
- [`docs/signing_vectors.json`](docs/signing_vectors.json) — Go ↔ Python interop fixture.
- [`go-key-service/internal/signing/README.md`](go-key-service/internal/signing/README.md) — signing API + benchmarks.
- [`go-key-service/internal/merkle/README.md`](go-key-service/internal/merkle/README.md) — Merkle tree + verifier.
