# contracts

Solidity anchoring contract that periodically commits Merkle roots from the
audit log to an Ethereum testnet. Tooling: Foundry.

## Setup

```sh
curl -L https://foundry.paradigm.xyz | bash
foundryup
forge init --no-git --no-commit .
```

(Re-runs of `forge init` in this directory are no-ops once `foundry.toml` exists.)

## Build / test

```sh
forge build
forge test
```
