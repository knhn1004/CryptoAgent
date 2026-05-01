import pytest

from cryptoagent.acl import ACL, CapabilityError


def test_grant_and_check():
    acl = ACL()
    acl.grant("agent-a", "read")
    assert acl.has("agent-a", "read")
    assert not acl.has("agent-a", "write")


def test_initial_grants():
    acl = ACL({"agent-a": ["read", "write"]})
    assert acl.has("agent-a", "read")
    assert acl.has("agent-a", "write")


def test_require_raises():
    acl = ACL()
    with pytest.raises(CapabilityError):
        acl.require("agent-a", "read")


def test_revoke():
    acl = ACL({"agent-a": ["read"]})
    acl.revoke("agent-a", "read")
    assert not acl.has("agent-a", "read")
    # idempotent
    acl.revoke("agent-a", "read")
    acl.revoke("ghost", "read")


def test_capabilities_snapshot_is_copy():
    acl = ACL({"a": ["x"]})
    snap = acl.capabilities("a")
    snap.add("y")
    assert acl.capabilities("a") == {"x"}
