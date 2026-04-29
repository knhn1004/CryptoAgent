import pytest

from cryptoagent.action import Action, ActionError


def sample() -> Action:
    return Action(
        schema_version=1,
        agent_id="agent-001",
        action_type="ping",
        target="peer-002",
        timestamp_ms=1700000000000,
        nonce="0123456789abcdef0123456789abcdef",
    )


def test_canonical_reference_vector() -> None:
    want = (
        b'{"action_type":"ping","agent_id":"agent-001",'
        b'"nonce":"0123456789abcdef0123456789abcdef",'
        b'"schema_version":1,"target":"peer-002","timestamp":1700000000000}'
    )
    assert sample().canonical() == want


def test_canonical_deterministic() -> None:
    a = sample()
    first = a.canonical()
    for _ in range(10):
        assert a.canonical() == first


@pytest.mark.parametrize(
    "bad_nonce",
    [
        "deadbeef",
        "0123456789ABCDEF0123456789abcdef",
        "Z" * 32,
        "0123456789abcdef0123456789abcde ",
    ],
)
def test_validate_rejects_bad_nonce(bad_nonce: str) -> None:
    a = Action(
        schema_version=1,
        agent_id="x",
        action_type="y",
        target="z",
        timestamp_ms=0,
        nonce=bad_nonce,
    )
    with pytest.raises(ActionError):
        a.validate()


def test_validate_rejects_wrong_schema_version() -> None:
    a = Action(
        schema_version=2,
        agent_id="x",
        action_type="y",
        target="z",
        timestamp_ms=0,
        nonce="0" * 32,
    )
    with pytest.raises(ActionError):
        a.validate()


@pytest.mark.parametrize("field", ["agent_id", "action_type", "target"])
def test_validate_rejects_empty_required_field(field: str) -> None:
    kwargs = dict(
        schema_version=1,
        agent_id="x",
        action_type="y",
        target="z",
        timestamp_ms=0,
        nonce="0" * 32,
    )
    kwargs[field] = ""
    with pytest.raises(ActionError):
        Action(**kwargs).validate()
