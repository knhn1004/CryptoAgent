"""Cross-language interop: Python must reproduce vectors from the Go signer."""

from __future__ import annotations

import json
from pathlib import Path

from nacl.signing import SigningKey

from cryptoagent.action import Action
from cryptoagent.signing import verify

VECTOR_PATH = Path(__file__).resolve().parents[2] / "docs" / "signing_vectors.json"


def load_vector():
    with VECTOR_PATH.open() as f:
        v = json.load(f)
    a = Action(
        schema_version=v["action"]["schema_version"],
        agent_id=v["action"]["agent_id"],
        action_type=v["action"]["action_type"],
        target=v["action"]["target"],
        timestamp_ms=v["action"]["timestamp"],
        nonce=v["action"]["nonce"],
    )
    return v, a


def test_canonical_matches_go():
    v, a = load_vector()
    assert a.canonical().hex() == v["canonical_hex"]


def test_python_signature_matches_go():
    v, a = load_vector()
    seed = bytes.fromhex(v["seed"])
    sk = SigningKey(seed)
    expected_pub = bytes.fromhex(v["public_key"])
    assert bytes(sk.verify_key) == expected_pub

    sig = bytes(sk.sign(a.canonical()).signature)
    assert sig.hex() == v["signature_hex"]


def test_python_verifies_go_signature():
    v, a = load_vector()
    pub = bytes.fromhex(v["public_key"])
    sig = bytes.fromhex(v["signature_hex"])
    verify(a, sig, pub)  # no exception
