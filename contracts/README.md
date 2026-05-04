# contracts

`AuditAnchor` is the on-chain witness for the off-chain RFC 6962 Merkle audit log. A trusted committer (the Go key-service) periodically posts `(treeSize, root, timestamp)` so any auditor can re-run consistency proofs against the live tree and detect rewrites the log operator can no longer hide.

Tooling: Foundry.

## Layout

```
contracts/
├── foundry.toml
├── src/AuditAnchor.sol            # the contract
├── test/AuditAnchor.t.sol         # forge tests (14 cases)
├── script/DeployAuditAnchor.s.sol # deploy script
└── lib/forge-std                  # submodule
```

## Setup

```sh
curl -L https://foundry.paradigm.xyz | bash
foundryup
git submodule update --init --recursive
```

## Build / test

```sh
cd contracts
forge build
forge test -vv
```

## Deploy (Sepolia)

```sh
export SEPOLIA_RPC_URL="https://..."
export DEPLOYER_PRIVATE_KEY="0x..."
export COMMITTER_ADDRESS="0x..."          # the address the Go service signs from
export ETHERSCAN_API_KEY="..."

forge script script/DeployAuditAnchor.s.sol \
  --rpc-url $SEPOLIA_RPC_URL \
  --private-key $DEPLOYER_PRIVATE_KEY \
  --broadcast --verify
```

After deployment, record the address in `docs/deployments.md` and pass it to the Go service via `ANCHOR_CONTRACT_ADDRESS`.

## Wiring the committer

The Go side talks to the contract through the foundry `cast` binary so we don't pull go-ethereum into `go.mod`. Required env vars on the keyserver:

| Variable                    | Required for `ANCHOR_MODE=cast` | Notes |
|-----------------------------|---------------------------------|-------|
| `ANCHOR_MODE`               | yes (`cast`, `dry-run`, or `off`) | `off` is the default |
| `ANCHOR_INTERVAL`           | optional                        | default `15m`, any Go duration |
| `ANCHOR_CONTRACT_ADDRESS`   | yes for `cast`                  | deployed `AuditAnchor` address |
| `ANCHOR_RPC_URL`            | yes for `cast`                  | Sepolia or any EVM JSON-RPC |
| `ANCHOR_PRIVATE_KEY`        | yes for `cast`                  | committer key (hex, 0x-prefixed) |
| `ANCHOR_CAST_BINARY`        | optional                        | path override; defaults to `cast` |

Indexer endpoint:

```
GET /v1/anchor/latest
{
  "id": 7,
  "tree_size": 42,
  "root_hex": "0xab…",
  "timestamp_ms": 1700000000500,
  "block_number": 12345,
  "tx_hash": "0xdeadbeef"
}
```

## Contract surface

```solidity
event AuditAnchored(
    uint256 indexed id,
    uint64  treeSize,
    bytes32 indexed root,
    uint64  blockNumber,
    uint64  timestamp
);

function commit(uint64 treeSize, bytes32 root, uint64 timestamp) external returns (uint256 id);
function latest() external view returns (Anchor memory);
function anchorAt(uint256 id) external view returns (Anchor memory);
function count() external view returns (uint256);

function setCommitter(address next) external;        // owner only
function transferOwnership(address next) external;   // two-step handover
function acceptOwnership() external;
```

Reverts:

- `EmptyTree` — `treeSize == 0`
- `TreeShrank(last, next)` — `treeSize <= last anchor`
- `NotCommitter` — only the configured committer may call `commit`
- `NotOwner` / `NotPendingOwner` — admin guards
- `ZeroAddress` — addresses passed to `constructor` / `setCommitter` / `transferOwnership` cannot be zero
