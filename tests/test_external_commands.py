from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest

from gvai.external_commands import (
    COMMAND_ALGORITHM,
    CommandAuthentication,
    ExternalCommandRejected,
    ExternalControlCommand,
    ExternalControlCommandVerifier,
    HMACSHA256Authenticator,
    InMemoryExternalControlState,
    sign_control_command,
)


NOW = 1_800_000_000
KEY = b"test-only-key-material-0123456789"
TARGET = "worker-7"
ISSUER = "control-service"


def make_command(command_id="00000000-0000-4000-8000-000000000001"):
    unsigned = ExternalControlCommand(
        version=1,
        command_id=command_id,
        command_type="shutdown",
        target_id=TARGET,
        issuer_id=ISSUER,
        issued_at=NOW - 1,
        expires_at=NOW + 60,
        auth=CommandAuthentication(
            algorithm=COMMAND_ALGORITHM,
            key_id="control-key-v1",
            signature="",
        ),
    )
    return sign_control_command(unsigned, KEY)


def make_verifier(state=None, authenticator=None, clock=None):
    return ExternalControlCommandVerifier(
        authenticator
        or HMACSHA256Authenticator({(ISSUER, "control-key-v1"): KEY}),
        state or InMemoryExternalControlState(),
        clock=clock or (lambda: NOW),
    )


def authorize(command, verifier=None, target=TARGET):
    return (verifier or make_verifier()).authorize(
        command.to_mapping() if isinstance(command, ExternalControlCommand) else command,
        expected_target_id=target,
    )


def test_canonical_bytes_are_deterministic_and_authenticate_all_fields():
    command = make_command()
    mapping = command.to_mapping()
    reversed_mapping = dict(reversed(list(mapping.items())))
    reversed_mapping["auth"] = dict(reversed(list(mapping["auth"].items())))

    assert command.canonical_bytes() == ExternalControlCommand.from_mapping(
        reversed_mapping
    ).canonical_bytes()
    assert authorize(command).command_id == command.command_id


@pytest.mark.parametrize(
    "field,value",
    [
        ("command_id", "00000000-0000-4000-8000-000000000002"),
        ("command_type", "restart"),
        ("target_id", "worker-8"),
        ("issuer_id", "other-controller"),
        ("issued_at", NOW),
        ("expires_at", NOW + 61),
        ("version", 2),
    ],
)
def test_mutated_signed_fields_are_rejected(field, value):
    mapping = make_command().to_mapping()
    mapping[field] = value

    with pytest.raises(ExternalCommandRejected):
        authorize(mapping)


def test_forged_signature_is_rejected():
    mapping = make_command().to_mapping()
    mapping["auth"]["signature"] = "0" * 64

    with pytest.raises(ExternalCommandRejected, match="authentication"):
        authorize(mapping)


@pytest.mark.parametrize(
    "field,value",
    [("key_id", "other-key"), ("algorithm", "HMAC-SHA1")],
)
def test_mutated_authentication_metadata_is_rejected(field, value):
    mapping = make_command().to_mapping()
    mapping["auth"][field] = value

    with pytest.raises(ExternalCommandRejected):
        authorize(mapping)


def test_issuer_identity_is_bound_to_configured_key():
    command = make_command()
    forged_issuer = replace(command, issuer_id="other-controller")
    signed = sign_control_command(forged_issuer, KEY)

    with pytest.raises(ExternalCommandRejected, match="authentication"):
        authorize(signed)


@pytest.mark.parametrize(
    "update",
    [
        {"extra": True},
        {"version": True},
        {"issued_at": True},
        {"auth": {"algorithm": COMMAND_ALGORITHM, "key_id": "control-key-v1"}},
    ],
)
def test_malformed_or_ambiguous_envelopes_are_rejected(update):
    mapping = make_command().to_mapping()
    mapping.update(update)

    with pytest.raises(ExternalCommandRejected):
        authorize(mapping)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"version":1,"version":1}',
        b'{"auth":{"key_id":"a","key_id":"b"}}',
        b'{"value":NaN}',
        b"\xff",
    ],
)
def test_duplicate_fields_and_malformed_json_are_rejected(raw):
    with pytest.raises(ExternalCommandRejected):
        authorize(raw)


def test_wrong_target_is_rejected_before_consumption():
    command = make_command()
    state = InMemoryExternalControlState()
    verifier = make_verifier(state=state)

    with pytest.raises(ExternalCommandRejected, match="target"):
        authorize(command, verifier=verifier, target="worker-other")

    assert authorize(command, verifier=verifier).command_id == command.command_id


@pytest.mark.parametrize(
    "issued_at,expires_at",
    [
        (NOW - 100, NOW - 10),
        (NOW + 6, NOW + 60),
        (NOW - 1, NOW + 301),
        (NOW + 2, NOW + 1),
    ],
)
def test_expired_future_or_overlong_commands_are_rejected(issued_at, expires_at):
    command = make_command()
    unsigned = replace(command, issued_at=issued_at, expires_at=expires_at)
    signed = sign_control_command(unsigned, KEY)

    with pytest.raises(ExternalCommandRejected):
        authorize(signed)


def test_clock_skew_boundary_is_explicit_and_accepted():
    command = make_command()
    unsigned = replace(command, issued_at=NOW - 10, expires_at=NOW - 5)
    signed = sign_control_command(unsigned, KEY)

    assert authorize(signed).command_id == command.command_id


def test_replay_is_rejected():
    command = make_command()
    verifier = make_verifier()

    assert authorize(command, verifier=verifier).command_id == command.command_id
    with pytest.raises(ExternalCommandRejected, match="consumed"):
        authorize(command, verifier=verifier)


def test_concurrent_replay_has_exactly_one_winner():
    command = make_command()
    verifier = make_verifier()

    def attempt(_):
        try:
            authorize(command, verifier=verifier)
            return "accepted"
        except ExternalCommandRejected:
            return "rejected"

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(attempt, range(32)))

    assert results.count("accepted") == 1
    assert results.count("rejected") == 31


@pytest.mark.parametrize("revoke", ["issuer", "command"])
def test_revoked_issuer_or_command_is_rejected(revoke):
    command = make_command()
    state = InMemoryExternalControlState()
    if revoke == "issuer":
        state.revoke_issuer(ISSUER)
    else:
        state.revoke_command(ISSUER, command.command_id)

    with pytest.raises(ExternalCommandRejected, match="revoked"):
        authorize(command, verifier=make_verifier(state=state))


def test_authenticator_exception_fails_closed():
    class BrokenAuthenticator:
        def verify(self, **_kwargs):
            raise RuntimeError("verification backend unavailable")

    with pytest.raises(ExternalCommandRejected, match="verification failed"):
        authorize(make_command(), verifier=make_verifier(authenticator=BrokenAuthenticator()))


def test_control_state_exception_fails_closed():
    class BrokenState:
        def consume_if_active(self, **_kwargs):
            raise RuntimeError("state backend unavailable")

        def revoke_issuer(self, _issuer_id):
            raise RuntimeError("state backend unavailable")

        def revoke_command(self, _issuer_id, _command_id):
            raise RuntimeError("state backend unavailable")

    with pytest.raises(ExternalCommandRejected, match="state is unavailable"):
        authorize(make_command(), verifier=make_verifier(state=BrokenState()))


def test_unavailable_clock_fails_closed():
    def broken_clock():
        raise RuntimeError("clock unavailable")

    with pytest.raises(ExternalCommandRejected, match="verification failed"):
        authorize(make_command(), verifier=make_verifier(clock=broken_clock))


def test_unknown_key_and_invalid_algorithm_are_rejected():
    authenticator = HMACSHA256Authenticator({})
    with pytest.raises(ExternalCommandRejected, match="authentication"):
        authorize(make_command(), verifier=make_verifier(authenticator=authenticator))



def test_hmac_keyring_rejects_undersized_keys():
    with pytest.raises(ValueError, match="configuration"):
        HMACSHA256Authenticator({(ISSUER, "weak-key"): b"too-short"})