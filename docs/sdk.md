# SDK Usage Guide

Adopt the trust layer with three decorators and an optional LangChain
wrapper. Every example below is verified by `sdk-python/tests/`.

## Install

```sh
cd sdk-python
python3.11 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev,langchain]"
```

## The Action

```python
from cryptoagent import Action

a = Action(
    schema_version=1,
    agent_id="alice",
    action_type="transfer_funds",
    target="treasury",
    timestamp_ms=1_700_000_000_000,
    nonce="0123456789abcdef0123456789abcdef",  # 32-char lowercase hex
)
canonical_bytes = a.canonical()
```

Canonical bytes are JSON with sorted keys and no whitespace; see
`docs/schema.md`. Both Go and Python produce **byte-identical**
canonical bytes — `tests/test_interop.py` enforces this against
`docs/signing_vectors.json`.

## Signing primitives

```python
from cryptoagent import generate_keypair, sign, verify

pub, priv = generate_keypair()           # 32-byte pub, 32-byte seed
sig = sign(a, priv)
verify(a, sig, pub)                      # raises SignatureError on tamper
```

Throughput on Apple M4: ~70k sign/sec, ~33k verify/sec including the
canonical encoding step.

## Decorator: `@signed_action`

Sign every call automatically. The signed action and its signature are
exposed to downstream code via `current_signed_action()` (a thread-local
context).

```python
from cryptoagent import signed_action, current_signed_action, verify

@signed_action(
    agent_id="alice",
    action_type="read_secret",
    target="vault/abc",
    private_key=alice_priv,
)
def read_secret(name: str) -> str:
    action, sig = current_signed_action()
    verify(action, sig, alice_pub)       # downstream layer can re-verify
    return f"secret:{name}"
```

`target` may be a callable `(args, kwargs) -> str` if the resource id
is derived from the call's arguments.

## Decorator: `@requires_capability`

Look up the agent in an ACL and reject unauthorized capabilities.

```python
from cryptoagent import ACL, requires_capability

acl = ACL({"alice": ["read_secret"]})

@requires_capability(acl, "read_secret")
def read_secret(name: str, *, agent_id: str) -> str:
    ...
```

The agent id is read from `kwargs["agent_id"]` by default; pass
`agent_id_arg="..."` to change the name.

## Orchestrator metric: `UnauthorizedMetrics`

`@requires_token` (the server-authoritative decorator from the
preceding section) takes an optional `metrics: UnauthorizedMetrics`
kwarg. Every rejection — whether the Go service returned
`expired`/`revoked`/`agent_mismatch`/`action_type_not_allowed`/
`target_not_allowed`, or the SDK rejected client-side
(missing token context, unreachable service) — increments a counter
keyed by the decorator's `action_type`. The decorator's
authoritative decision is unchanged; metrics only observe.

```python
from cryptoagent import (
    UnauthorizedMetrics, requires_token, signed_action, token_context,
)

metrics = UnauthorizedMetrics()

@signed_action(agent_id="alice", action_type="transfer_funds",
               target="vault/treasury", private_key=alice_priv)
@requires_token(client, action_type="transfer_funds",
                target="vault/treasury", metrics=metrics)
def transfer(amount: int) -> str:
    ...

# After traffic has run:
metrics.count("transfer_funds")    # int
metrics.snapshot()                 # {action_type: count}
```

This counter is the success-metric input from the proposal — the
dashboard reads it as "out-of-scope action rejections per type".

## Decorator: `@multi_sig` (and the `Gate`)

For *critical* actions, the SDK enforces a t-of-n threshold of distinct
valid signers. There are two equivalent shapes:

### Shape A — wrap the function

```python
from cryptoagent import Gate, multi_sig, sign

gate = Gate()

@multi_sig(gate, action_type="transfer_funds", threshold=2)
def transfer(amount: int) -> str:
    return f"moved {amount}"

# Caller passes the action + signatures as kwargs:
out = transfer(amount=10, action=proposed, signatures=sig_pairs)
```

### Shape B — invariant + explicit `gate.execute`

```python
from cryptoagent import Gate, gated

gate = Gate({"transfer_funds": 2})

@gated(gate, "transfer_funds")
def transfer(amount: int, *, agent_id: str) -> str:
    return f"moved {amount}"

out = gate.execute(proposed, sig_pairs, transfer, 10, agent_id="alice")

# Direct call -> BypassError, and gate.bypass_metrics() increments.
```

Shape B is what the LangChain wrapper uses, because LangChain calls a
tool's `func` itself and we don't control the call site.

## Composition

The decorators stack. Outer wraps inner; the innermost runs last.

```python
from cryptoagent import (
    ACL, Gate, gated, requires_capability, signed_action, generate_keypair,
)

@gated(gate, "transfer_funds")
@requires_capability(acl, "transfer_funds")
@signed_action(
    agent_id="alice", action_type="transfer_funds",
    target="treasury", private_key=alice_priv,
)
def transfer(amount: int, *, agent_id: str) -> str:
    ...
```

Order matters only insofar as `@gated` must be outermost (so it can
reject before any signing/ACL work).

## LangChain integration

```python
from cryptoagent.langchain_integration import signed_tool

tool = signed_tool(
    name="transfer_funds",
    description="Move funds from agent account to treasury.",
    func=transfer_impl,
    agent_id="alice",
    private_key=alice_priv,
    target="treasury",
    acl=acl,
    capability="transfer_funds",
    gate=gate,
    threshold=2,
)
```

`tool` is a `langchain_core.tools.Tool`. Call it via
`gate.execute(action, signatures, tool.func, *args, **kwargs)`. See
[`examples/langchain_agent.py`](../sdk-python/examples/langchain_agent.py)
for a runnable end-to-end script.

## Bypass metric

```python
gate.bypass_metrics()      # {"transfer_funds": 3, ...}
gate.bypass_count()        # total
gate.bypass_count("x")     # per action_type
```

Increment when a `@gated` function is called outside `gate.execute`.
The metric is per-process; aggregate across replicas with your
preferred sink.

## Replay protection (verifier-side)

Anyone implementing a verifier (e.g. a downstream policy engine) must
also enforce the rules from `docs/schema.md`:

* `abs(now_ms - action.timestamp_ms) <= 30_000`
* `(agent_id, nonce)` not seen within the last 600 s
* `nonce` is exactly 32 lowercase hex characters

The signing/ACL/gate primitives in the SDK are necessary but not
sufficient; pair them with a verifier that owns the nonce window.
