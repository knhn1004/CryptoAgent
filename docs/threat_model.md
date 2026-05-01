# Threat Model

Scope: cryptographic guardrails for an agent process that calls
external tools and APIs. The trust layer is meant to make individual
agent actions *attributable*, *gated*, and *auditable*; it is not a
full sandbox.

## Assets

1. **Agent private keys** — held in the key-service or a local secret.
   Loss = forgery.
2. **The capability ACL** — controls which agent may invoke which
   action type.
3. **The Merkle audit log** — append-only history of every signed
   action. Tampering must be detectable by any observer.
4. **The on-chain root commits** — provide an external, immutable
   witness against rewrites.

## Adversary model

We consider three classes:

* **Compromised agent process** — adversary executes arbitrary code in
  one agent's process and may issue actions in that agent's name.
* **Compromised tool / external dependency** — adversary controls a
  tool or LangChain plugin invoked by the agent.
* **Compromised log operator** — adversary controls the host running
  the Merkle log and may try to rewrite history without detection.

Out of scope: total compromise of the key service (can mint signatures
for any agent), supply-chain attack on Python or PyNaCl, attacks on
the underlying Ed25519 primitive.

## Threats addressed

| # | Threat | Mitigation |
|---|--------|------------|
| T1 | Action attribution: actor unknown after the fact | Every action carries an Ed25519 signature over canonical bytes. `verify(action, sig, pub)` recovers the signer. |
| T2 | Action replay (same signed bytes resubmitted) | `(agent_id, nonce)` cache + `±30 s` timestamp window per `docs/schema.md`. |
| T3 | Cross-language signature drift | `docs/signing_vectors.json` fixture, asserted by Go and Python tests. |
| T4 | Privilege escalation by an agent | `@requires_capability` against an `ACL`. |
| T5 | Single-agent unilateral action on critical operations | `Gate` enforces t-of-n distinct valid signers; `ThresholdNotMetError` on violation. |
| T6 | Bypassing the gate by calling the function directly | `@gated` invariant decorator: direct call → `BypassError` and `gate.bypass_metrics()` increments. |
| T7 | Silent rewrite of the audit log | RFC 6962 Merkle tree + consistency proofs. `Verifier.VerifyHistoricalRoot` flags any in-range tamper with a hex-bearing diagnostic. |
| T8 | Compromise of the log host hiding T7 | Periodic on-chain commits via the anchor contract: an external observer can re-run the consistency proof against any committed root. |

## Threats *not* addressed

* **Pre-action prompt injection.** The trust layer signs the action a
  prompt induced — not the prompt. If the LLM is convinced to call
  `transfer_funds(amount=10_000)`, multi-sig limits the blast radius
  but does not prevent the call from being proposed.
* **Side-channel exfiltration of private keys.** No HSM, no
  attestation; secret protection is whatever the deployment provides.
* **Denial of service.** Rate limiting, quotas, and abusive-nonce
  detection are not in scope.
* **Time skew attacks beyond ±30 s.** Verifier clocks must be
  reasonably synced; large skew either rejects honest actions or
  enlarges the replay window.
* **Collusion of ≥ t signers.** By construction, the gate trusts t
  signers. Choosing t and the signer set is an organizational
  decision, not a cryptographic one.

## Residual risks and mitigations roadmap

* **In-memory keystore in dev**: production deployment must back
  `keystore.KeyStore` with a durable, encrypted-at-rest implementation.
  Tracked under epic #1 follow-ups.
* **Live Merkle tree is in-process**: a node restart drops the log
  unless leaves are persisted out-of-band. The CLI (`merkle-verify`)
  already supports rebuilding from a hex leaves file, so durable leaf
  storage is the only missing piece.
* **Bypass metric is per-process**: aggregate via Prometheus or
  similar in deployment.
* **Anchor cadence is policy**: the committer daemon (out of scope
  for the SDK) decides how often to publish `(size, root)`. Longer
  cadence → larger window in which a log compromise is undetectable.

## Verification checklist

Before shipping a new agent on top of the SDK:

1. Each critical action has a `@signed_action` decorator with a real
   `private_key` (not a test fixture).
2. Each critical action has either `@multi_sig` or `@gated` plus a
   matching `Gate` configuration.
3. The verifier downstream of the agent re-checks the signature and
   the replay window from `docs/schema.md`.
4. The deployment scrapes `gate.bypass_metrics()` into a sink that
   alerts on non-zero values.
5. The deployment runs `merkle-verify` (or
   `POST /v1/merkle/verify`) at the same cadence as the on-chain
   commits.
