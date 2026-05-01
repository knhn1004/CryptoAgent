"""Ed25519 sign/verify over the canonical action schema.

Mirror of go-key-service/internal/signing/signing.go. Both libraries MUST
produce byte-identical signatures for equal (seed, action) inputs;
docs/signing_vectors.json is the authoritative cross-language fixture.

Keys here use the 32-byte raw Ed25519 seed (== first 32 bytes of Go's
ed25519.PrivateKey, which stores seed||public_key).
"""

from __future__ import annotations

import os

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from .action import Action

PUBLIC_KEY_LEN = 32
PRIVATE_KEY_SEED_LEN = 32
SIGNATURE_LEN = 64


class SignatureError(Exception):
    """Verification failed."""


def generate_keypair() -> tuple[bytes, bytes]:
    """Returns ``(public_key_32, private_key_seed_32)``."""
    seed = os.urandom(PRIVATE_KEY_SEED_LEN)
    sk = SigningKey(seed)
    return bytes(sk.verify_key), seed


def sign(action: Action, private_key: bytes) -> bytes:
    if len(private_key) != PRIVATE_KEY_SEED_LEN:
        raise ValueError(
            f"private key must be {PRIVATE_KEY_SEED_LEN}-byte seed, got {len(private_key)}"
        )
    sk = SigningKey(private_key)
    msg = action.canonical()
    return bytes(sk.sign(msg).signature)


def verify(action: Action, signature: bytes, public_key: bytes) -> None:
    if len(public_key) != PUBLIC_KEY_LEN:
        raise ValueError(f"public key must be {PUBLIC_KEY_LEN} bytes, got {len(public_key)}")
    if len(signature) != SIGNATURE_LEN:
        raise SignatureError(f"signature must be {SIGNATURE_LEN} bytes, got {len(signature)}")
    vk = VerifyKey(public_key)
    msg = action.canonical()
    try:
        vk.verify(msg, signature)
    except BadSignatureError as e:
        raise SignatureError("invalid signature") from e
