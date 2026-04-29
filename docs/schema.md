# Agent Action Schema (v1)

Canonical signed message format used by every CryptoAgent component (Go key-service, Python SDK, dashboard, on-chain anchor). Defined once here; both runtime libraries (`go-key-service/internal/action` and `sdk-python/cryptoagent/action.py`) MUST produce byte-identical canonical encodings for equal inputs.

## Action

```jsonc
{
  "schema_version": 1,
  "agent_id":       "<string>",   // stable opaque id, e.g. ULID
  "action_type":    "<string>",   // snake_case verb, e.g. "transfer_funds"
  "target":         "<string>",   // opaque resource id, application-defined
  "timestamp":      <int64>,      // unix milliseconds, UTC
  "nonce":          "<string>"    // 32-char lowercase hex (16 random bytes)
}
```

All six fields are **required**. Unknown fields are rejected.

## Canonical encoding

JSON, with these rules (subset of RFC 8785 sufficient for our schema):

1. UTF-8, no BOM.
2. Object keys sorted ascending by Unicode code point.
3. No insignificant whitespace (no spaces, no newlines).
4. Strings: minimal JSON escaping (`"`, `\`, control chars `\u00xx`).
5. Integers serialized without decimal point or exponent.

The canonical bytes are what gets signed (`sign(canonical(action))`) and what gets hashed before Merkle append (`hash(canonical(action) || signature)`).

Reference vector (must round-trip identically in Go and Python):

```
input:
  schema_version=1
  agent_id="agent-001"
  action_type="ping"
  target="peer-002"
  timestamp=1700000000000
  nonce="0123456789abcdef0123456789abcdef"

canonical bytes:
  {"action_type":"ping","agent_id":"agent-001","nonce":"0123456789abcdef0123456789abcdef","schema_version":1,"target":"peer-002","timestamp":1700000000000}
```

## Replay protection

A verifier MUST reject an action if any of the following hold:

| Check          | Rule                                                                 |
|----------------|----------------------------------------------------------------------|
| Schema version | `schema_version != 1`                                                |
| Timestamp skew | `abs(server_now_ms - timestamp) > 30_000` (±30 s)                    |
| Nonce window   | `(agent_id, nonce)` already seen within the last `600_000` ms (10 m) |
| Nonce shape    | `nonce` is not exactly 32 lowercase hex chars                        |

Verifiers SHOULD persist seen `(agent_id, nonce)` for at least `window = skew + nonce_window = 30 s + 600 s = 630 s` to close the boundary case.

## Versioning

Bump `SchemaVersion` (Go) / `SCHEMA_VERSION` (Python) and add a new section here for any breaking change to field set, types, or canonical rules. Old verifiers MUST reject newer versions until upgraded.
