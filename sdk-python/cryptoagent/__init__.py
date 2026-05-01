"""CryptoAgent Python SDK — signed actions, multi-sig gate, ACL, and a
LangChain wrapper. See ``examples/langchain_agent.py`` for end-to-end
usage."""

from .acl import ACL, CapabilityError
from .action import (
    MAX_SKEW_MS,
    NONCE_HEX_LEN,
    NONCE_WINDOW_MS,
    SCHEMA_VERSION,
    Action,
    ActionError,
)
from .decorators import (
    current_signed_action,
    multi_sig,
    requires_capability,
    signed_action,
)
from .multisig import (
    BypassError,
    Gate,
    ThresholdNotMetError,
    gated,
)
from .signing import (
    SignatureError,
    generate_keypair,
    sign,
    verify,
)

__all__ = [
    "ACL",
    "Action",
    "ActionError",
    "BypassError",
    "CapabilityError",
    "Gate",
    "MAX_SKEW_MS",
    "NONCE_HEX_LEN",
    "NONCE_WINDOW_MS",
    "SCHEMA_VERSION",
    "SignatureError",
    "ThresholdNotMetError",
    "current_signed_action",
    "gated",
    "generate_keypair",
    "multi_sig",
    "requires_capability",
    "sign",
    "signed_action",
    "verify",
]
