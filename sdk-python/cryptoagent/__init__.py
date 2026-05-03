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
from .proposal import (
    AuditSink,
    InMemoryAuditSink,
    LocalPeer,
    MerkleHTTPAuditSink,
    Peer,
    Proposal,
    ProposalError,
    ProposalFlow,
    ReplayError,
    ThresholdNotReached,
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
    "AuditSink",
    "BypassError",
    "CapabilityError",
    "Gate",
    "InMemoryAuditSink",
    "LocalPeer",
    "MAX_SKEW_MS",
    "MerkleHTTPAuditSink",
    "NONCE_HEX_LEN",
    "NONCE_WINDOW_MS",
    "Peer",
    "Proposal",
    "ProposalError",
    "ProposalFlow",
    "ReplayError",
    "SCHEMA_VERSION",
    "SignatureError",
    "ThresholdNotMetError",
    "ThresholdNotReached",
    "current_signed_action",
    "gated",
    "generate_keypair",
    "multi_sig",
    "requires_capability",
    "sign",
    "signed_action",
    "verify",
]
