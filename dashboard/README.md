# dashboard

React + TypeScript SPA visualizing the CryptoAgent Merkle audit tree
and live agent interactions. Reads from `go-key-service` over HTTP/SSE.

## Setup

```sh
npm install
```

## Dev

Run the key service with CORS enabled for the Vite dev server, then
start the dashboard:

```sh
# terminal 1 — key-service (in repo root)
cd ../go-key-service
KEYSERVER_CORS_ORIGINS=http://localhost:5173 ANCHOR_MODE=dry-run \
  go run ./cmd/keyserver

# terminal 2 — dashboard
npm run dev
```

The dashboard is at <http://localhost:5173>. Override the API base
with `VITE_API_BASE` if the key service is not on `:8080`.

## Build / test

```sh
npm run build       # type-check + bundle to dist/
npm test            # vitest
```

## What it shows

- **Header** — schema version, live tree size, current Merkle root.
- **Merkle audit log (top-left)** — live root, last on-chain anchor
  (block number, size, age), and the last 16 appended leaves.
- **Agent interaction graph (top-right)** — agents on the left,
  targets on the right, edges = signed actions, edges colored by
  `action_type`. Edges go red when every observed instance was
  rejected; animated when some were rejected.
- **Live event stream (bottom)** — appended (green left rail) and
  rejected events (red, or amber for ACL/token denials) in reverse
  chronological order. The anchor badge in the header flashes when a
  new on-chain anchor lands.

## Data sources

| Endpoint                | Use                                    |
|-------------------------|----------------------------------------|
| `GET  /v1/audit/events` | SSE feed: appended + rejected events.  |
| `GET  /v1/merkle/head`  | Live (size, root) for the header tile. |
| `GET  /v1/anchor/latest`| Last on-chain anchor for highlights.   |
| `GET  /v1/keys`         | Agent registry seed.                   |

The SSE stream emits `{kind: "appended" \| "rejected", seq, …}`.
`seq` is monotonic across both kinds — the dashboard uses it to
deduplicate after reconnect (`?since=<lastSeq+1>`).
