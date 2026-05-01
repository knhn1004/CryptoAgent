import pytest

from cryptoagent.action import Action
from cryptoagent.signing import (
    SignatureError,
    generate_keypair,
    sign,
    verify,
)


def sample_action() -> Action:
    return Action(
        schema_version=1,
        agent_id="agent-001",
        action_type="ping",
        target="peer-002",
        timestamp_ms=1_700_000_000_000,
        nonce="0123456789abcdef0123456789abcdef",
    )


def test_sign_verify_round_trip():
    pub, priv = generate_keypair()
    a = sample_action()
    sig = sign(a, priv)
    verify(a, sig, pub)  # no exception


def test_verify_wrong_key_rejected():
    _, priv = generate_keypair()
    other_pub, _ = generate_keypair()
    a = sample_action()
    sig = sign(a, priv)
    with pytest.raises(SignatureError):
        verify(a, sig, other_pub)


def test_verify_tampered_action_rejected():
    pub, priv = generate_keypair()
    a = sample_action()
    sig = sign(a, priv)
    tampered = Action(
        schema_version=a.schema_version,
        agent_id=a.agent_id,
        action_type=a.action_type,
        target="peer-evil",
        timestamp_ms=a.timestamp_ms,
        nonce=a.nonce,
    )
    with pytest.raises(SignatureError):
        verify(tampered, sig, pub)


def test_verify_tampered_signature_rejected():
    pub, priv = generate_keypair()
    a = sample_action()
    sig = bytearray(sign(a, priv))
    sig[0] ^= 0xFF
    with pytest.raises(SignatureError):
        verify(a, bytes(sig), pub)


def test_sign_bad_key_length():
    a = sample_action()
    with pytest.raises(ValueError):
        sign(a, b"\x00" * 16)


def test_verify_bad_key_length():
    a = sample_action()
    with pytest.raises(ValueError):
        verify(a, b"\x00" * 64, b"\x00" * 8)


def test_verify_bad_sig_length():
    pub, _ = generate_keypair()
    a = sample_action()
    with pytest.raises(SignatureError):
        verify(a, b"\x00" * 32, pub)
