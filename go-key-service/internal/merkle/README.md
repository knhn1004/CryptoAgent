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
// In-memory tree
t := merkle.New()
idx, err := t.Append(payload)        // returns leaf index
t.Root()                              // current head, 32 B
t.RootAt(size)                        // root over first N leaves

// Inclusion proofs (issue #10)
proof, _ := t.Proof(idx)              // RFC 6962 audit path
merkle.VerifyInclusion(payload, idx, t.Size(), proof, t.Root())
t.ProofAt(idx, size)                  // proof against a historical size

// Consistency proofs (issue #12)
t.ProofForRange(oldSize, newSize)
merkle.VerifyConsistency(oldRoot, newRoot, oldSize, newSize, proof)

// Persistent tree (flat-file, fsync per append)
t, err := merkle.Open("/var/lib/merkle/leaves.log")
defer t.Close()
t.Append(payload)                     // also writes 32 B + fsyncs

v := merkle.NewVerifier(t)
report, err := v.VerifyHistoricalRoot(historicalRoot, historicalSize)
```

The flat-file format is a concatenation of 32-byte leaf hashes; size on
disk is always `Size() * 32` bytes. Reopening the same path reloads the
exact tree state.

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
