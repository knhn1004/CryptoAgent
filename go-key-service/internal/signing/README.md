# `internal/signing`

Ed25519 sign/verify over the canonical action bytes (see `docs/schema.md`).
Pairs with `sdk-python/cryptoagent/signing.py`; both sides MUST produce
byte-identical signatures for equal inputs.

## API

```go
sig, err := signing.Sign(action, priv)         // priv is ed25519.PrivateKey (64 B)
err     := signing.Verify(action, sig, pub)     // pub is ed25519.PublicKey (32 B)
pub, priv, err := signing.GenerateKey(rand.Reader)
```

Errors: `ErrInvalidSignature`, `ErrInvalidKeyLength`.

## Cross-language interop

`docs/signing_vectors.json` is the authoritative fixture. Regenerate with:

```sh
go run ./internal/signing/vector_gen > ../docs/signing_vectors.json
```

Both `internal/signing/interop_test.go` and `sdk-python/tests/test_interop.py`
assert equality against this file.

## Benchmarks

Apple M4, Go 1.26 (`go test -bench=. -benchmem -run=^$ ./internal/signing`):

```
BenchmarkSign-10        85732       14173 ns/op    1128 B/op    24 allocs/op
BenchmarkVerify-10      42068       29785 ns/op    1064 B/op    23 allocs/op
```

≈ **70k sign/sec, 33k verify/sec** single-threaded, including the canonical
JSON encoding step.
