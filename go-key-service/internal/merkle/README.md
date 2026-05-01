# `internal/merkle`

RFC 6962-style append-only Merkle tree + consistency-proof verifier
backing the root-consistency job (issue #12).

## Hashing

```
leaf hash      = SHA-256(0x00 || data)
internal node  = SHA-256(0x01 || left || right)
empty root     = SHA-256("")
```

Per `docs/schema.md`, the `data` for a real action is
`canonical(action) || signature`.

## API surface

```go
t := merkle.New()
t.Append(payload)                   // returns leaf index
t.Root()                             // current head, 32 B
t.RootAt(size)                       // root over first N leaves
t.ProofForRange(oldSize, newSize)    // RFC 6962 consistency proof

merkle.VerifyConsistency(oldRoot, newRoot, oldSize, newSize, proof)

v := merkle.NewVerifier(t)
report, err := v.VerifyHistoricalRoot(historicalRoot, historicalSize)
```

`VerificationReport` includes `OK`, hex-encoded live and historical
roots, both sizes, and a human-readable `Message` (e.g. `derived old
root <hex> != <hex>` on tamper).

## CLI

```sh
go run ./cmd/merkle-verify \
  --historical-root <hex> \
  --historical-size 32 \
  --leaves-file leaves.hex
```

Exit 0 on consistent, 1 on divergence.

## HTTP

`internal/merkle/http.Handler(v)` returns `POST /v1/merkle/verify`
returning the report as JSON (200 on consistent, 422 on divergence,
400 on bad input).
