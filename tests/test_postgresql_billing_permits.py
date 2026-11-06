"""No private keys: published public verification vector and mocked context tests."""

from dataclasses import replace
import json
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from gvai.postgresql_billing_permits import (
    ConsumptionIntent, ConsumptionUnavailable, DOMAIN, ExpectedPermit, Lifecycle,
    LifecycleRecord, MAX_PERMIT_BYTES, Outcome, Permit, PermitDenied,
    PermitOperation, PermitVerifier, SignedPermit, authorize_intent, finish_intent,
    parse_permit, transition,
)


# RFC 8032 section 7.1, TEST 1: public key and signature of the empty message.
PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
SIGNATURE = bytes.fromhex(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f"
    "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


def permit():
    return Permit(
        1, "1" * 32, "2" * 64, "3" * 32, "review-authority", "bootstrap-supervisor",
        "approval-v1", 100, 200, PermitOperation.CREATE, Lifecycle.APPROVED, 0,
        "4" * 64, (("harness", "5" * 64), ("migration-004", "6" * 64)),
    )


def expected(value=None):
    value = permit() if value is None else value
    return ExpectedPermit(**{
        name: getattr(value, name) for name in ExpectedPermit.__dataclass_fields__
    })


def record(value=None):
    value = permit() if value is None else value
    return LifecycleRecord(value.run_id, value.predecessor, value.generation, value.identity_digest)


def wire(value=None):
    return SignedPermit(permit() if value is None else value, SIGNATURE).wire_bytes()


class InMemoryConsumption:
    """Deliberately non-durable; only a unit-test model of the CAS contract."""

    def __init__(self):
        self.pending = []

    def consume_once(self, intent):
        if any(
            (old.issuer, old.operation_id) == (intent.issuer, intent.operation_id)
            or old.expected == intent.expected for old in self.pending
        ):
            return False
        self.pending.append(intent)
        return True


def verifier():
    return PermitVerifier({("review-authority", "approval-v1"): PUBLIC})


@pytest.fixture
def context_signature_mock():
    # These tests prove context/consumption logic, NOT valid signed-permit success.
    with patch.object(Ed25519PublicKey, "from_public_bytes") as load:
        load.return_value.verify.return_value = None
        yield load.return_value.verify


def test_published_public_verification_vector_and_forgery():
    key = Ed25519PublicKey.from_public_bytes(PUBLIC)
    key.verify(SIGNATURE, b"")
    with pytest.raises(InvalidSignature):
        key.verify(SIGNATURE, b"altered")
    # The published signature is not a signature of our canonical permit.
    with pytest.raises(PermitDenied, match="signature_rejected"):
        verifier().verify(wire(), expected(), now=100)


def test_tampered_signature_rejected_without_consumption():
    signed = SignedPermit(permit(), b"\x00" * 64)
    with pytest.raises(PermitDenied, match="signature_rejected"):
        verifier().verify(signed.wire_bytes(), expected(), now=150)


def test_canonical_round_trip_and_domain():
    value = permit()
    assert parse_permit(wire()).permit == value
    assert value.canonical_bytes() == DOMAIN + json.dumps(
        value.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    assert b"signature" not in value.canonical_bytes()


@pytest.mark.parametrize("changes", [
    {"version": True}, {"version": 2}, {"run_id": "../run"},
    {"run_id": "0" * 32}, {"nonce": "0" * 64}, {"nonce": "A" * 64},
    {"operation_id": ""}, {"issuer": "embedded key"}, {"audience": None},
    {"key_id": "x\n"}, {"issued_at": True}, {"expires_at": float("inf")},
    {"expires_at": 100}, {"expires_at": 401}, {"generation": True},
    {"generation": -1}, {"identity_digest": "bad"}, {"artifacts": ()},
    {"artifacts": (("z", "a" * 64), ("a", "b" * 64))},
    {"artifacts": (("a", "a" * 64), ("a", "b" * 64))},
    {"operation": "create"}, {"predecessor": "APPROVED"},
    {"operation": PermitOperation.MIGRATE},
])
def test_invalid_permit_shapes(changes):
    with pytest.raises(PermitDenied):
        replace(permit(), **changes).canonical_bytes()


@pytest.mark.parametrize("bad", [
    b"", b"x" * (MAX_PERMIT_BYTES + 1), b"\xff", b"[]", b"null",
    b'{"permit":{},"permit":{},"signature":""}',
    b'{"permit":{},"signature":"","public_key":"not-trusted"}',
])
def test_invalid_envelope(bad):
    with pytest.raises(PermitDenied):
        parse_permit(bad)


def test_noncanonical_unknown_fields_and_nested_duplicates():
    for changed in (
        b" " + wire(),
        wire().replace(b'"version":1', b'"version":1,"version":1'),
        wire().replace(b'"version":1', b'"version":1,"public_key":"untrusted"'),
        wire().replace(b'"generation":0', b'"generation":0.0'),
        wire().replace(b'"create"', b'[]'),
    ):
        with pytest.raises(PermitDenied):
            parse_permit(changed)


@pytest.mark.parametrize("old,new", [
    (b'"issuer":"review-authority"', b'"issuer":"r\xc3\xa9view-authority"'),
    (b'"issuer":"review-authority"', b'"issuer":"r\\u00e9view-authority"'),
    (b'"issuer":"review-authority"', b'"issuer":"re\\u0301view-authority"'),
    (b'"issuer":"review-authority"', b'"issuer":"\\ud800"'),
    (b'"issuer":"review-authority"', b'"issuer":"\\uZZZZ"'),
    (b'"issuer":"review-authority"', b'"issuer":"review-\\u0061uthority"'),
    (b'"generation":0', b'"generation":NaN'),
    (b'"issued_at":100', b'"issued_at":NaN'),
    (b'"expires_at":200', b'"expires_at":NaN'),
])
def test_unicode_and_nan_wire_denied_before_consumption(old, new):
    candidate = wire().replace(old, new)
    assert candidate != wire()
    storage = InMemoryConsumption()
    with pytest.raises(PermitDenied):
        authorize_intent(verifier(), candidate, expected(), record(), storage, now=150)
    assert storage.pending == []


@pytest.mark.parametrize("changes", [
    {"run_id": "a" * 32}, {"nonce": "a" * 64}, {"issuer": "other"},
    {"audience": "test-runner"}, {"operation": PermitOperation.START},
    {"predecessor": Lifecycle.CREATED}, {"generation": 1},
    {"generation": False}, {"identity_digest": "a" * 64},
    {"artifacts": (("harness", "0" * 64),)},
])
def test_exact_expected_context_required(changes, context_signature_mock):
    with pytest.raises(PermitDenied, match="context_mismatch"):
        verifier().verify(wire(), replace(expected(), **changes), now=150)
    context_signature_mock.assert_not_called()


@pytest.mark.parametrize("now", [0, 99, 200, 201, True, -1, 150.0])
def test_expiry_future_and_invalid_clock(now, context_signature_mock):
    with pytest.raises(PermitDenied):
        verifier().verify(wire(), expected(), now=now)
    context_signature_mock.assert_not_called()


@pytest.mark.parametrize("now", [100, 199])
def test_valid_time_boundary_context_only(now, context_signature_mock):
    assert verifier().verify(wire(), expected(), now=now) == permit()
    context_signature_mock.assert_called_once_with(SIGNATURE, permit().canonical_bytes())


def test_trust_keys_external_issuer_bound_and_immutable(context_signature_mock):
    for keys in (
        {("other", "approval-v1"): PUBLIC},
        {("review-authority", "different"): PUBLIC},
    ):
        with pytest.raises(PermitDenied, match="untrusted_signing_key"):
            PermitVerifier(keys).verify(wire(), expected(), now=150)
    pins = {("review-authority", "approval-v1"): PUBLIC}
    check = PermitVerifier(pins)
    pins.clear()
    assert check.verify(wire(), expected(), now=150) == permit()
    with pytest.raises(AttributeError):
        check._keys = {}
    with pytest.raises(AttributeError):
        del check._keys


@pytest.mark.parametrize("keys", [{}, {("issuer", "key"): b"x"}, {"key": PUBLIC}])
def test_invalid_trust_configuration(keys):
    with pytest.raises(PermitDenied):
        PermitVerifier(keys)


def test_replay_and_parallel_predecessor_cas(context_signature_mock):
    storage = InMemoryConsumption()
    intent = authorize_intent(verifier(), wire(), expected(), record(), storage, now=150)
    assert intent.target is Lifecycle.CREATED
    assert record().state is Lifecycle.APPROVED
    with pytest.raises(PermitDenied, match="consumption_rejected"):
        authorize_intent(verifier(), wire(), expected(), record(), storage, now=150)
    second = replace(permit(), operation_id="a" * 32)
    with pytest.raises(PermitDenied, match="consumption_rejected"):
        authorize_intent(verifier(), wire(second), expected(second), record(), storage, now=150)


def test_bad_signature_never_consumed():
    storage = InMemoryConsumption()
    with pytest.raises(PermitDenied, match="signature_rejected"):
        authorize_intent(verifier(), wire(), expected(), record(), storage, now=150)
    assert storage.pending == []


@pytest.mark.parametrize("changes", [
    {"generation": 1}, {"run_id": "a" * 32}, {"state": Lifecycle.CREATED},
    {"identity_digest": "a" * 64},
])
def test_wrong_lifecycle_record_never_consumed(changes, context_signature_mock):
    storage = InMemoryConsumption()
    with pytest.raises(PermitDenied, match="record_mismatch"):
        authorize_intent(
            verifier(), wire(), expected(), replace(record(), **changes), storage, now=150,
        )
    assert storage.pending == []


@pytest.mark.parametrize("result", [False, None, 1, "true"])
def test_only_literal_storage_success_accepted(result, context_signature_mock):
    class Storage:
        def consume_once(self, intent):
            return result
    with pytest.raises(PermitDenied, match="consumption_rejected"):
        authorize_intent(verifier(), wire(), expected(), record(), Storage(), now=150)


def test_unknown_consumption_redacted_and_not_retried(context_signature_mock):
    class Storage:
        calls = 0

        def consume_once(self, intent):
            self.calls += 1
            raise ConsumptionUnavailable("synthetic-sensitive-error")
    storage = Storage()
    with pytest.raises(PermitDenied) as failure:
        authorize_intent(verifier(), wire(), expected(), record(), storage, now=150)
    assert str(failure.value) == "consumption_unavailable_or_ambiguous"
    assert failure.value.__suppress_context__
    assert storage.calls == 1


@pytest.mark.parametrize("error_type", [RuntimeError, ValueError, TimeoutError])
def test_unexpected_storage_errors_propagate_without_success_or_retry(
    error_type, context_signature_mock,
):
    error = error_type("synthetic-adapter-failure")

    class Storage:
        calls = 0

        def consume_once(self, intent):
            self.calls += 1
            raise error

    storage = Storage()
    with pytest.raises(error_type) as failure:
        authorize_intent(verifier(), wire(), expected(), record(), storage, now=150)
    assert failure.value is error
    assert storage.calls == 1


FORWARD = {
    (Lifecycle.APPROVED, PermitOperation.CREATE): Lifecycle.CREATED,
    (Lifecycle.CREATED, PermitOperation.INITIALIZE): Lifecycle.INITIALIZED,
    (Lifecycle.INITIALIZED, PermitOperation.START): Lifecycle.STARTED,
    (Lifecycle.STARTED, PermitOperation.ATTEST): Lifecycle.ATTESTED,
    (Lifecycle.ATTESTED, PermitOperation.MIGRATE): Lifecycle.MIGRATED,
    (Lifecycle.MIGRATED, PermitOperation.TEST): Lifecycle.TESTED,
    (Lifecycle.STOPPED, PermitOperation.CLEANUP): Lifecycle.CLEANED,
    (Lifecycle.CLEANUP_INCOMPLETE, PermitOperation.CLEANUP): Lifecycle.CLEANED,
}
STOPPABLE = {
    Lifecycle.CREATED, Lifecycle.INITIALIZED, Lifecycle.STARTED, Lifecycle.ATTESTED,
    Lifecycle.MIGRATED, Lifecycle.TESTED, Lifecycle.FAILED, Lifecycle.UNKNOWN,
}


@pytest.mark.parametrize("state", list(Lifecycle))
@pytest.mark.parametrize("operation", list(PermitOperation))
def test_exhaustive_transition_matrix(state, operation):
    target = FORWARD.get((state, operation))
    if operation is PermitOperation.STOP and state in STOPPABLE:
        target = Lifecycle.STOPPED
    if target is None:
        with pytest.raises(PermitDenied, match="invalid_transition"):
            transition(state, operation)
    else:
        assert transition(state, operation) is target


@pytest.mark.parametrize("outcome,state", [
    (Outcome.SUCCEEDED, Lifecycle.CREATED), (Outcome.FAILED, Lifecycle.FAILED),
    (Outcome.UNKNOWN, Lifecycle.UNKNOWN),
])
def test_outcome_candidate_is_not_durable_or_operation_proof(outcome, state, context_signature_mock):
    intent = authorize_intent(
        verifier(), wire(), expected(), record(), InMemoryConsumption(), now=150,
    )
    result = finish_intent(intent, outcome)
    assert result == replace(record(), state=state, generation=1)
    assert intent.expected == record()
    with pytest.raises(PermitDenied):
        finish_intent(intent, Outcome.CLEANUP_INCOMPLETE)
    with pytest.raises(PermitDenied):
        finish_intent(replace(intent, target=Lifecycle.CLEANED), Outcome.SUCCEEDED)


def test_cleanup_crash_retry_and_no_rollback():
    intent = ConsumptionIntent(
        "review-authority", "3" * 32, "a" * 64,
        replace(record(), state=Lifecycle.STOPPED), PermitOperation.CLEANUP, Lifecycle.CLEANED,
    )
    result = finish_intent(intent, Outcome.CLEANUP_INCOMPLETE)
    assert result.state is Lifecycle.CLEANUP_INCOMPLETE
    assert transition(result.state, PermitOperation.CLEANUP) is Lifecycle.CLEANED
    assert transition(Lifecycle.UNKNOWN, PermitOperation.STOP) is Lifecycle.STOPPED
    for state in (Lifecycle.FAILED, Lifecycle.UNKNOWN, Lifecycle.CLEANED):
        with pytest.raises(PermitDenied):
            transition(state, PermitOperation.START)


@pytest.mark.parametrize("outcome", list(Outcome))
def test_finish_intent_denies_exact_generation_exhaustion(outcome):
    exhausted = replace(record(), state=Lifecycle.STOPPED, generation=2**63 - 2)
    exhausted.validate()
    intent = ConsumptionIntent(
        "review-authority", "3" * 32, "a" * 64, exhausted,
        PermitOperation.CLEANUP, Lifecycle.CLEANED,
    )
    with pytest.raises(PermitDenied, match="^generation_exhausted$"):
        finish_intent(intent, outcome)
    assert intent.expected == exhausted


@pytest.mark.parametrize("generation", [0, 1, 2**63 - 4, 2**63 - 3])
@pytest.mark.parametrize("outcome,state", [
    (Outcome.SUCCEEDED, Lifecycle.CLEANED),
    (Outcome.FAILED, Lifecycle.FAILED),
    (Outcome.UNKNOWN, Lifecycle.UNKNOWN),
    (Outcome.CLEANUP_INCOMPLETE, Lifecycle.CLEANUP_INCOMPLETE),
])
def test_finish_intent_returns_valid_record_below_exhaustion(generation, outcome, state):
    predecessor = replace(record(), state=Lifecycle.STOPPED, generation=generation)
    predecessor.validate()
    intent = ConsumptionIntent(
        "review-authority", "3" * 32, "a" * 64, predecessor,
        PermitOperation.CLEANUP, Lifecycle.CLEANED,
    )
    result = finish_intent(intent, outcome)
    result.validate()
    assert result == replace(predecessor, state=state, generation=generation + 1)
    assert intent.expected == predecessor


@pytest.mark.parametrize("generation", [
    -1, True, False, 0.0, None, "1", 2**63 - 1, 2**63, 2**64,
])
@pytest.mark.parametrize("outcome", list(Outcome))
def test_invalid_record_generations_cannot_complete(generation, outcome):
    predecessor = replace(record(), state=Lifecycle.STOPPED, generation=generation)
    with pytest.raises(PermitDenied, match="^invalid_record$"):
        predecessor.validate()
    intent = ConsumptionIntent(
        "review-authority", "3" * 32, "a" * 64, predecessor,
        PermitOperation.CLEANUP, Lifecycle.CLEANED,
    )
    with pytest.raises(PermitDenied, match="^invalid_record$"):
        finish_intent(intent, outcome)


@pytest.mark.parametrize("generation", [2**63 - 3, 2**63 - 2, 2**63 - 1])
def test_permit_generation_validation_is_unchanged(generation):
    candidate = replace(permit(), generation=generation)
    assert parse_permit(wire(candidate)).permit == candidate


@pytest.mark.parametrize("generation", [-1, True, False, 0.0, None, "1", 2**63, 2**64])
def test_invalid_permit_generations_remain_denied(generation):
    with pytest.raises(PermitDenied, match="^invalid_generation$"):
        replace(permit(), generation=generation).canonical_bytes()


@pytest.mark.parametrize("state,operation", [
    ("APPROVED", PermitOperation.CREATE),
    (Lifecycle.APPROVED, "create"),
    (None, PermitOperation.CREATE),
])
def test_untyped_transition_denied(state, operation):
    with pytest.raises(PermitDenied, match="invalid_transition"):
        transition(state, operation)


def test_no_execution_or_signing_dependencies():
    import ast
    import inspect
    import gvai.postgresql_billing_permits as module

    source = inspect.getsource(module)
    tree = ast.parse(source)
    assert "Ed25519PrivateKey" not in source
    assert ".sign(" not in source
    forbidden = {
        "connect", "execute", "open", "mkdir", "unlink", "rmdir", "write_text",
        "write_bytes", "Popen", "system", "exec", "eval",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else (
                node.func.id if isinstance(node.func, ast.Name) else ""
            )
            assert name not in forbidden
