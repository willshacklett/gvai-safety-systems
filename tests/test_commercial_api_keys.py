from concurrent.futures import ThreadPoolExecutor
from dataclasses import fields, replace
from unittest.mock import Mock

import pytest

from gvai import commercial_api_keys as api_keys

from gvai.commercial_api_keys import (
    API_KEY_PREFIX,
    ApiKeyOperationError,
    ApiKeyRecord,
    CustomerApiKeys,
    InMemoryApiKeyStore,
)
from gvai.commercial_identity import (
    CommercialAuthorizer,
    CommercialAuthorizationReason as Reason,
    CommercialCapability as Capability,
    CommercialResourceKind as Kind,
    CommercialResourceOwnership as Ownership,
)


@pytest.fixture
def boundary():
    store = InMemoryApiKeyStore()
    now = [1000]
    keys = CustomerApiKeys(store, verifier_secret=b"test-only-pepper-" * 2, clock=lambda: now[0])
    issued = keys.issue(
        principal_id="customer-a", tenant_id="tenant-a",
        capabilities=frozenset({Capability.EVALUATE}), expires_at=2000,
    )
    secret = issued.take_secret()

    class OwnershipStore:
        def lookup(self, resource_id):
            return {
                "project-a": Ownership("project-a", "tenant-a", Kind.EVALUATION),
                "project-b": Ownership("project-b", "tenant-b", Kind.EVALUATION),
                "usage-a": Ownership("usage-a", "tenant-a", Kind.USAGE),
            }.get(resource_id)

    authorizer = CommercialAuthorizer(keys, OwnershipStore(), clock=lambda: now[0])
    return keys, store, issued, secret, now, authorizer


def test_issuance_and_existing_authorization_boundary(boundary):
    keys, store, issued, secret, _, authorizer = boundary
    assert secret.startswith(API_KEY_PREFIX)
    assert issued.take_secret() is None
    assert keys.verify(secret).tenant_id == "tenant-a"
    record = store.lookup(issued.key_id)
    assert record.created_at == 1000
    assert record.expires_at == 2000
    assert len(record.verifier) == 32
    assert secret not in repr(record) + repr(issued) + repr(keys) + repr(store)
    assert authorizer.authorize(secret, Capability.EVALUATE, "project-a").allowed
    assert authorizer.authorize(secret, Capability.EVALUATE, "project-b").reason is Reason.TENANT_MISMATCH
    assert authorizer.authorize(secret, Capability.READ_USAGE, "usage-a").reason is Reason.CAPABILITY_NOT_GRANTED
    assert not authorizer.authorize(secret, "supervisor:stop", "project-a").allowed
    assert keys.revoke(issued.key_id)
    assert keys.verify(secret) is None
    assert not authorizer.authorize(secret, Capability.EVALUATE, "project-a").allowed


def test_exclusive_expiry_and_no_cached_allow(boundary):
    keys, _, _, secret, now, authorizer = boundary
    now[0] = 1999
    assert keys.verify(secret) is not None
    now[0] = 2000
    assert keys.verify(secret) is None
    assert not authorizer.authorize(secret, Capability.EVALUATE, "project-a").allowed


def test_in_flight_verification_can_precede_revocation_but_next_call_denies(boundary, monkeypatch):
    """The prototype does not guarantee immediate cancellation of in-flight checks."""
    keys, store, issued, secret, _, authorizer = boundary
    original_lookup = store.lookup

    def lookup_then_revoke(key_id):
        prior_record = original_lookup(key_id)
        assert keys.revoke(key_id) is True
        return prior_record

    monkeypatch.setattr(store, "lookup", lookup_then_revoke)
    decision = authorizer.authorize(secret, Capability.EVALUATE, "project-a")
    assert original_lookup(issued.key_id).revoked is True
    assert decision.allowed is True
    assert keys.verify(secret) is None
    assert authorizer.authorize(secret, Capability.EVALUATE, "project-a").allowed is False


def test_trusted_clock_rollback_can_restore_expired_key_validity(boundary):
    """Rollback resistance remains a production blocker, not a prototype guarantee."""
    keys, _, _, secret, now, authorizer = boundary
    now[0] = 2000
    assert keys.verify(secret) is None
    assert authorizer.authorize(secret, Capability.EVALUATE, "project-a").allowed is False
    now[0] = 1500
    assert keys.verify(secret) is not None
    assert authorizer.authorize(secret, Capability.EVALUATE, "project-a").allowed is True


@pytest.mark.parametrize("credential", [
    None, "", b"opaque", {}, {"tenant_id": "tenant-a"},
    "supervisor-secret", "x" * 10000,
    API_KEY_PREFIX + "0" * 32 + "_" + "0" * 64,
    API_KEY_PREFIX + "A" * 32 + "_" + "0" * 64,
    API_KEY_PREFIX + "0" * 32 + "_" + "\u00e9" * 64,
])
def test_unknown_and_malformed_credentials_deny(boundary, credential):
    keys, _, _, _, _, authorizer = boundary
    assert keys.verify(credential) is None
    assert not authorizer.authorize(credential, Capability.EVALUATE, "project-a").allowed


def test_mutations_and_claim_injection_deny(boundary):
    keys, _, _, secret, _, authorizer = boundary
    for candidate in (
        secret + "\n", " " + secret, secret.upper(),
        secret[:-1] + ("0" if secret[-1] != "0" else "1"),
        secret + ":tenant-b:supervisor:stop",
        {"credential": secret, "tenant_id": "tenant-b", "capabilities": list(Capability)},
    ):
        assert keys.verify(candidate) is None
        assert not authorizer.authorize(candidate, Capability.EVALUATE, "project-a").allowed


@pytest.mark.parametrize("configuration", [None, b"", b"x" * 31, "x" * 32, bytearray(32)])
def test_missing_or_invalid_verifier_configuration_fails_closed(boundary, configuration):
    _, store, _, secret, _, _ = boundary
    keys = CustomerApiKeys(store, verifier_secret=configuration, clock=lambda: 1000)
    assert keys.verify(secret) is None
    with pytest.raises(ApiKeyOperationError, match="API key issuance failed"):
        keys.issue(principal_id="customer", tenant_id="tenant", capabilities=frozenset(Capability), expires_at=2000)


@pytest.mark.parametrize("changes", [
    {"principal_id": ""}, {"tenant_id": "gvai-internal"}, {"tenant_id": None},
    {"capabilities": frozenset({"evaluation:run"})},
    {"capabilities": frozenset({"supervisor:stop"})},
    {"capabilities": list(Capability)}, {"expires_at": True},
    {"expires_at": 1000}, {"expires_at": -1}, {"expires_at": float("inf")},
])
def test_invalid_trusted_assignments_never_persist(boundary, changes):
    keys, store, _, _, _, _ = boundary
    insert = Mock(wraps=store.insert_if_absent)
    store.insert_if_absent = insert
    arguments = dict(principal_id="customer", tenant_id="tenant", capabilities=frozenset(Capability), expires_at=2000)
    arguments.update(changes)
    with pytest.raises(ApiKeyOperationError):
        keys.issue(**arguments)
    insert.assert_not_called()


@pytest.mark.parametrize("changes", [
    {"key_id": "0" * 32}, {"principal_id": None}, {"tenant_id": "gvai-internal"},
    {"capabilities": frozenset({"supervisor:stop"})},
    {"capabilities": frozenset({"evaluation:run"})}, {"capabilities": []},
    {"created_at": True}, {"created_at": -1}, {"created_at": 2000},
    {"expires_at": True}, {"expires_at": 1000}, {"revoked": "false"},
    {"verifier": b"short"}, {"verifier": "x" * 32},
])
def test_corrupt_store_records_deny(boundary, changes):
    keys, store, issued, secret, _, _ = boundary
    record = replace(store.lookup(issued.key_id), **changes)
    store.lookup = lambda _key_id: record
    assert keys.verify(secret) is None


@pytest.mark.parametrize("record", [None, {}, object.__new__(ApiKeyRecord)])
def test_missing_or_incomplete_store_records_deny(boundary, record):
    keys, store, _, secret, _, _ = boundary
    store.lookup = lambda _key_id: record
    assert keys.verify(secret) is None


@pytest.mark.parametrize("now", [True, None, "1000", -1, float("nan"), float("inf"), 999])
def test_invalid_time_or_time_before_creation_denies(boundary, now):
    keys, _, _, secret, clock, _, = boundary
    clock[0] = now
    assert keys.verify(secret) is None


def test_secure_system_randomness_and_deterministic_test_only_fixture(boundary, monkeypatch):
    keys, _, _, _, _, _ = boundary
    random_hex = Mock(side_effect=["1" * 32, "2" * 64])
    monkeypatch.setattr(api_keys.secrets, "token_hex", random_hex)
    issued = keys.issue(principal_id="customer", tenant_id="tenant", capabilities=frozenset(Capability), expires_at=2000)
    assert issued.take_secret() == API_KEY_PREFIX + "1" * 32 + "_" + "2" * 64
    assert [call.args for call in random_hex.call_args_list] == [(16,), (32,)]


def test_collision_retries_never_overwrite_existing_key(boundary, monkeypatch):
    keys, store, issued, secret, _, _ = boundary
    original = store.lookup(issued.key_id)
    random_hex = Mock(side_effect=[issued.key_id, "2" * 64] * 3)
    monkeypatch.setattr(api_keys.secrets, "token_hex", random_hex)
    with pytest.raises(ApiKeyOperationError):
        keys.issue(principal_id="attacker", tenant_id="tenant-b", capabilities=frozenset(Capability), expires_at=2000)
    assert random_hex.call_count == 6
    assert store.lookup(issued.key_id) == original
    assert keys.verify(secret).principal_id == "customer-a"
    random_hex.side_effect = [issued.key_id, "2" * 64, "3" * 32, "4" * 64]
    replacement = keys.issue(principal_id="customer-a", tenant_id="tenant-a", capabilities=frozenset(Capability), expires_at=2000)
    assert replacement.key_id == "3" * 32
    assert keys.verify(replacement.take_secret()) is not None


def test_collisions_cannot_overwrite_revoked_key_records(boundary, monkeypatch):
    keys, store, issued, secret, _, _ = boundary
    assert keys.revoke(issued.key_id) is True
    revoked_record = store.lookup(issued.key_id)
    assert revoked_record.revoked is True
    random_hex = Mock(side_effect=[issued.key_id, "2" * 64] * 3)
    monkeypatch.setattr(api_keys.secrets, "token_hex", random_hex)
    with pytest.raises(ApiKeyOperationError, match="API key issuance failed"):
        keys.issue(principal_id="attacker", tenant_id="tenant-b", capabilities=frozenset(Capability), expires_at=2000)
    assert random_hex.call_count == 6
    assert store.lookup(issued.key_id) == revoked_record
    assert keys.verify(secret) is None
    assert keys.verify(API_KEY_PREFIX + issued.key_id + "_" + "2" * 64) is None


def test_atomic_store_insertion_and_one_time_handoff_under_threads(boundary):
    _, store, issued, _, _, _ = boundary
    record = replace(store.lookup(issued.key_id), key_id="a" * 32)
    handoff = api_keys.IssuedApiKey("a" * 32, "test-only-handoff")
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda _index: store.insert_if_absent(record), range(32))) == 1
        presentations = list(pool.map(lambda _index: handoff.take_secret(), range(32)))
    assert presentations.count("test-only-handoff") == 1
    assert presentations.count(None) == 31


def test_constant_time_verifier_comparison_for_valid_and_wrong_secrets(boundary, monkeypatch):
    keys, _, _, secret, _, _ = boundary
    compare = Mock(wraps=api_keys.hmac.compare_digest)
    monkeypatch.setattr(api_keys.hmac, "compare_digest", compare)
    assert keys.verify(secret) is not None
    assert keys.verify(secret[:-1] + ("0" if secret[-1] != "0" else "1")) is None
    assert compare.call_count == 2
    assert all(type(value) is bytes and len(value) == 32 for call in compare.call_args_list for value in call.args)


@pytest.mark.parametrize("dependency", ["lookup", "digest", "compare", "clock"])
def test_verification_failures_deny_without_secret_leakage(boundary, dependency, monkeypatch, caplog, capsys):
    keys, store, issued, secret, _, authorizer = boundary

    def fail(*_args):
        raise RuntimeError(secret)

    if dependency == "lookup":
        monkeypatch.setattr(store, "lookup", fail)
    elif dependency == "digest":
        monkeypatch.setattr(keys, "_digest", fail)
    elif dependency == "compare":
        monkeypatch.setattr(api_keys.hmac, "compare_digest", fail)
    else:
        monkeypatch.setattr(keys, "_clock", fail)
    assert keys.verify(secret) is None
    decision = authorizer.authorize(secret, Capability.EVALUATE, "project-a")
    assert not decision.allowed
    captured = capsys.readouterr()
    assert secret not in repr(decision) + repr(issued) + repr(keys) + caplog.text + captured.out + captured.err


@pytest.mark.parametrize("dependency", ["insert_if_absent", "randomness", "digest", "clock"])
def test_issuance_failures_suppress_underlying_errors(boundary, dependency, monkeypatch, caplog, capsys):
    keys, store, _, secret, _, _ = boundary

    def fail(*_args):
        raise RuntimeError(secret)

    if dependency == "insert_if_absent":
        monkeypatch.setattr(store, dependency, fail)
    elif dependency == "randomness":
        monkeypatch.setattr(api_keys.secrets, "token_hex", fail)
    else:
        monkeypatch.setattr(keys, "_digest" if dependency == "digest" else "_clock", fail)
    with pytest.raises(ApiKeyOperationError) as error:
        keys.issue(principal_id="customer", tenant_id="tenant", capabilities=frozenset(Capability), expires_at=2000)
    assert error.value.__context__ is None
    captured = capsys.readouterr()
    assert secret not in repr(error.value) + caplog.text + captured.out + captured.err


def test_revocation_failure_unknown_and_repeat_behavior(boundary, monkeypatch):
    keys, store, issued, secret, _, _ = boundary
    assert not keys.revoke(None)
    assert not keys.revoke(secret)
    assert not keys.revoke("0" * 32)
    assert keys.revoke(issued.key_id)
    assert keys.revoke(issued.key_id)
    assert keys.verify(secret) is None
    monkeypatch.setattr(store, "revoke", Mock(side_effect=RuntimeError(secret)))
    assert keys.revoke(issued.key_id) is False


def test_active_key_revocation_store_failure_is_not_success_and_does_not_leak(boundary, monkeypatch, caplog, capsys):
    keys, store, issued, secret, _, authorizer = boundary
    active_record = store.lookup(issued.key_id)
    assert active_record.revoked is False
    assert keys.verify(secret) is not None
    revoke = Mock(side_effect=RuntimeError(secret))
    monkeypatch.setattr(store, "revoke", revoke)
    result = keys.revoke(issued.key_id)
    assert result is False
    revoke.assert_called_once_with(issued.key_id)
    assert store.lookup(issued.key_id) == active_record
    assert keys.verify(secret) is not None
    decision = authorizer.authorize(secret, Capability.EVALUATE, "project-a")
    assert decision.allowed is True
    captured = capsys.readouterr()
    assert secret not in repr(result) + repr(decision) + caplog.text + captured.out + captured.err


def test_customer_rotation_with_explicit_overlap_and_revocation(boundary):
    keys, _, issued, secret, _, authorizer = boundary
    replacement = keys.issue(principal_id="customer-a", tenant_id="tenant-a", capabilities=frozenset(Capability), expires_at=2000)
    new_secret = replacement.take_secret()
    assert replacement.key_id != issued.key_id
    assert keys.verify(secret) is not None
    assert keys.verify(new_secret) is not None
    assert keys.revoke(issued.key_id)
    assert not authorizer.authorize(secret, Capability.EVALUATE, "project-a").allowed
    assert authorizer.authorize(new_secret, Capability.READ_USAGE, "usage-a").allowed


def test_verifier_secret_rotation_requires_reissuance_and_does_not_restore_revoked_keys(boundary):
    keys, store, issued, secret, _, _ = boundary
    same = CustomerApiKeys(store, verifier_secret=b"test-only-pepper-" * 2, clock=lambda: 1000)
    rotated = CustomerApiKeys(store, verifier_secret=b"new-test-only-pepper-" * 2, clock=lambda: 1000)
    assert same.verify(secret) is not None
    assert rotated.verify(secret) is None
    new_key = rotated.issue(principal_id="customer-a", tenant_id="tenant-a", capabilities=frozenset(Capability), expires_at=2000)
    new_secret = new_key.take_secret()
    assert rotated.verify(new_secret) is not None
    assert keys.verify(new_secret) is None
    assert keys.revoke(issued.key_id)
    assert same.verify(secret) is None


def test_store_and_identity_output_contain_no_plaintext_key(boundary):
    keys, store, issued, secret, _, _ = boundary
    record = store.lookup(issued.key_id)
    assert all(getattr(record, field.name) != secret for field in fields(record))
    assert record.verifier != secret.encode()
    assert secret not in repr(keys.verify(secret))
    assert record.verifier.hex() not in repr(record)


def test_empty_grants_grant_nothing_and_both_narrow_grants_can_be_issued(boundary):
    keys, _, _, _, _, authorizer = boundary
    empty = keys.issue(principal_id="customer-a", tenant_id="tenant-a", capabilities=frozenset(), expires_at=2000)
    secret = empty.take_secret()
    assert keys.verify(secret).capabilities == frozenset()
    assert not authorizer.authorize(secret, Capability.EVALUATE, "project-a").allowed
    both = keys.issue(principal_id="customer-a", tenant_id="tenant-a", capabilities=frozenset(Capability), expires_at=2000)
    secret = both.take_secret()
    assert authorizer.authorize(secret, Capability.EVALUATE, "project-a").allowed
    assert authorizer.authorize(secret, Capability.READ_USAGE, "usage-a").allowed


def test_api_key_path_cannot_call_evaluation_or_stop(boundary, monkeypatch):
    from gvai import evaluation
    from gvai.external_control import GVExternalControlPlane
    from gvai.runtime_policy import GVRuntimePolicy

    def forbidden(*_args, **_kwargs):
        pytest.fail("customer key operations cannot invoke evaluation or STOP")

    monkeypatch.setattr(evaluation, "evaluate_request", forbidden)
    for control in (GVExternalControlPlane, GVRuntimePolicy):
        monkeypatch.setattr(control, "evaluate_internal_shutdown", forbidden)
        monkeypatch.setattr(control, "evaluate_command", forbidden)
    keys, _, issued, secret, _, authorizer = boundary
    assert authorizer.authorize(secret, Capability.EVALUATE, "project-a").allowed
    assert not authorizer.authorize(secret, "shutdown", "project-a").allowed
    assert keys.revoke(issued.key_id)


def test_customer_keys_and_supervisor_commands_are_not_interchangeable(boundary):
    from gvai.effects import make_action
    from gvai.external_commands import (
        COMMAND_ALGORITHM, CommandAuthentication, ExternalControlCommand,
        ExternalControlCommandVerifier, HMACSHA256Authenticator,
        InMemoryExternalControlState, sign_control_command,
    )
    from gvai.external_control import GVExternalControlPlane

    keys, _, issued, secret, _, _ = boundary
    supervisor_key = b"independent-supervisor-test-key-1234"
    command = sign_control_command(ExternalControlCommand(
        version=1, command_id="00000000-0000-4000-8000-000000000001",
        command_type="shutdown", target_id="worker", issuer_id="supervisor",
        issued_at=999, expires_at=1100,
        auth=CommandAuthentication(COMMAND_ALGORITHM, "stop-key", ""),
    ), supervisor_key)
    verifier = ExternalControlCommandVerifier(
        HMACSHA256Authenticator({("supervisor", "stop-key"): supervisor_key}),
        InMemoryExternalControlState(), clock=lambda: 1000,
    )
    action = make_action("ordinary", {"low_impact"})
    plane = GVExternalControlPlane()
    rejected = plane.evaluate_command(action, secret, expected_target_id="worker", verifier=verifier)
    assert not rejected.allowed and not rejected.halted
    forged = sign_control_command(command, secret.encode())
    rejected = plane.evaluate_command(action, forged.to_mapping(), expected_target_id="worker", verifier=verifier)
    assert not rejected.allowed and not rejected.halted
    assert keys.verify(command.to_mapping()) is None
    assert keys.verify(supervisor_key.decode()) is None
    assert keys.revoke(issued.key_id)
    assert plane.evaluate_internal_shutdown(action).halted
    assert plane.evaluate_command(action, command.to_mapping(), expected_target_id="worker", verifier=verifier).halted
