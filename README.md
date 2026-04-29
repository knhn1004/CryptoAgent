# CryptoAgent

Cryptographic guardrails for multi-agent AI systems. CS 168 (Spring 2026) project.

## Layout

| Path               | Purpose                                                              |
|--------------------|----------------------------------------------------------------------|
| `go-key-service/`  | Go HTTP service: Ed25519 keypairs, signing/verification primitives.  |
| `sdk-python/`      | Python SDK + LangChain decorators consumed by agent code.            |
| `dashboard/`       | React + TypeScript dashboard (Merkle tree + agent interaction view). |
| `contracts/`       | Solidity anchoring contract (Foundry) for periodic root commits.     |
| `docs/`            | Specs — start with [`docs/schema.md`](docs/schema.md).               |

## Phases

1. Core crypto infra (key service, signing, schema) — epic #1
2. Merkle audit log + on-chain anchoring — epic #2
3. Multi-sig consensus, ACL, Python SDK — epic #3
4. Dashboard + demo — epic #4

## Local checks

```sh
# Go
( cd go-key-service && go test ./... )

# Python
( cd sdk-python && pip install -e ".[dev]" && pytest -q && ruff check . )

# Pre-commit (one-time install)
pip install pre-commit && pre-commit install
```

CI mirrors these on every PR (see `.github/workflows/`).
