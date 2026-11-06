from dataclasses import FrozenInstanceError, replace
import json

import pytest

from gvai.checkout_attempts import (
    MAX_GENERATION, AttemptCommitUnknown, AttemptDenied, AttemptState as State,
    AttemptStorageUnavailable, CheckoutApproval, CheckoutAttempt,
    CheckoutAttemptStore, FrozenCheckoutRequest, SessionStatus,
    VerifiedCheckoutSession, claim_attempt, claim_recovery, close_verified,
    confirm_session, expire_unsent, freeze_checkout_request, mark_unknown,
    prepare_attempt, quarantine_attempt, resolve_prepare, validate_recovery,
)
from gvai.sandbox_checkout import (
    AuthenticatedCheckoutContext, CheckoutMembership, SandboxCheckoutBuilder,
    SandboxCheckoutConfig,
)


def frozen(**changes):
    class Memberships:
        def lookup(self, issuer, principal, tenant):
            return CheckoutMembership(issuer, principal, tenant, True, True)

    tenant = changes.pop("tenant", "tenant-a")
    attempt = changes.pop("attempt", "1" * 32)
    issuer = changes.pop("issuer", "identity-provider")
    principal = changes.pop("principal", "subject-a")
    account = changes.pop("account", "acct_SyntheticSandbox")
    price = changes.pop("price", "price_SyntheticMonthly")
    intent = SandboxCheckoutBuilder(
        SandboxCheckoutConfig(
            account, "sandbox", price, True, "https://billing.example/success",
            "https://billing.example/cancel",
        ), Memberships(), clock=lambda: 100,
    ).build(
        {}, context=AuthenticatedCheckoutContext(issuer, principal, tenant, 1000),
        attempt_id=attempt,
    )
    return freeze_checkout_request(intent, **{
        "membership_ref": 7, "customer_id": "cus_Synthetic",
        "adapter_version": "checkout-v1", "api_version": "synthetic-api-v1",
        **changes,
    })


def approval(request=None, **changes):
    return CheckoutApproval(**{
        "request": frozen() if request is None else request,
        "expires_at": 1000, "tenant_active": True, "membership_active": True,
        "checkout_approved": True, "price_approved": True,
        "customer_association_verified": True, "pilot_present": False,
        "subscription_admitted": False, **changes,
    })


def prepared(request=None):
    request = frozen() if request is None else request
    return prepare_attempt(request, approval(request), now=100, expires_at=200)


def dispatch(record=None):
    record = prepared() if record is None else record
    return claim_attempt(
        record, approval(record.request), expected_generation=record.generation,
        lease_id="worker-a", now=101, lease_seconds=20,
    )


def session(request=None, **changes):
    return VerifiedCheckoutSession(**{
        "request": frozen() if request is None else request,
        "session_id": "cs_test_Synthetic", "observed_at": 102,
        "expires_at": 300, "status": SessionStatus.OPEN, **changes,
    })


def attach(record=None, evidence=None, **changes):
    record = dispatch() if record is None else record
    return confirm_session(
        record, session(record.request) if evidence is None else evidence, **{
            "expected_generation": record.generation, "lease_id": record.lease_id,
            "now": 103, **changes,
        },
    )


def test_frozen_exact_allowlisted_adapter_parameters_and_deep_immutability():
    request = frozen()
    assert json.loads(request.parameters) == {
        "mode": "subscription", "customer": "cus_Synthetic",
        "line_items": [{"price": "price_SyntheticMonthly", "quantity": 1}],
        "success_url": "https://billing.example/success",
        "cancel_url": "https://billing.example/cancel",
        "client_reference_id": "1" * 32,
    }
    assert len(request.fingerprint) == 64
    assert request == frozen()
    assert request.key == ("acct_SyntheticSandbox", "sandbox", "1" * 32)
    record = prepared(request)
    for obj, field, value in (
        (request, "customer_id", "cus_Other"),
        (request.intent, "quantity", 2),
        (record, "state", State.CLOSED_VERIFIED),
    ):
        with pytest.raises(FrozenInstanceError):
            setattr(obj, field, value)
    assert record.holds_tenant_slot


@pytest.mark.parametrize("changes", [
    {"tenant": "tenant-b"}, {"issuer": "other-provider"}, {"principal": "subject-b"},
    {"membership_ref": 8}, {"customer_id": "cus_Other"}, {"account": "acct_Other"},
    {"price": "price_OtherApproved"}, {"adapter_version": "checkout-v2"},
    {"api_version": "synthetic-api-v2"}, {"attempt": "2" * 32},
])
def test_complete_fingerprint_binds_every_association_and_adapter_parameter(changes):
    assert frozen(**changes).fingerprint != frozen().fingerprint


@pytest.mark.parametrize("parameters", [
    b"{}", b'{"customer":"cus_Other"}', b'{"metadata":{"tenant":"other"}}',
    b'{"quantity":true}', b'{"quantity":NaN}', b'{"a":1,"a":2}',
    b"\xff", b'{"value":"\\ud800"}', "", {}, bytearray(b"{}"),
])
def test_changed_or_malformed_outbound_bytes_denied(parameters):
    with pytest.raises(AttemptDenied, match="invalid_frozen_request"):
        replace(frozen(), parameters=parameters)


def test_equivalent_noncanonical_bytes_are_not_the_frozen_request():
    request = frozen()
    with pytest.raises(AttemptDenied, match="invalid_frozen_request"):
        replace(request, parameters=json.dumps(json.loads(request.parameters), indent=2).encode())


@pytest.mark.parametrize("customer", [None, {}, object(), True, "\ud800", ""])
def test_factory_denies_invalid_customer_before_serialization(customer):
    with pytest.raises(AttemptDenied, match="invalid_frozen_request"):
        frozen(customer_id=customer)


@pytest.mark.parametrize("changes", [
    {"quantity": True}, {"unit_amount": 9900.0}, {"version": True},
    {"request_fingerprint": "0" * 64}, {"idempotency_key": "client-chosen"},
    {"quantity": 2}, {"mode": "payment"}, {"environment": "live"},
    {"price_id": "price_Other"}, {"success_url": "https://other.example/path"},
])
def test_forged_intent_rejected_instead_of_trusting_fingerprint_field(changes):
    request = frozen()
    with pytest.raises(AttemptDenied):
        freeze_checkout_request(
            replace(request.intent, **changes), membership_ref=7,
            customer_id="cus_Synthetic", adapter_version="checkout-v1",
            api_version="synthetic-api-v1",
        )


@pytest.mark.parametrize("field,value", [
    ("membership_ref", True), ("membership_ref", 0), ("membership_ref", -1),
    ("membership_ref", MAX_GENERATION + 1), ("customer_id", "cus_"),
    ("customer_id", "client@example.com"), ("customer_id", "\ud800"),
    ("adapter_version", None), ("api_version", True),
])
def test_invalid_frozen_identity_types(field, value):
    with pytest.raises(AttemptDenied):
        replace(frozen(), **{field: value})


@pytest.mark.parametrize("field,value", [
    ("tenant_active", False), ("membership_active", False),
    ("checkout_approved", False), ("price_approved", False),
    ("customer_association_verified", False), ("pilot_present", True),
    ("subscription_admitted", True), ("checkout_approved", 1),
    ("pilot_present", 0), ("expires_at", True), ("expires_at", 100),
])
def test_prepare_and_claim_revalidate_current_authorization(field, value):
    request = frozen()
    denied = approval(request, **{field: value})
    with pytest.raises(AttemptDenied, match="authorization_denied"):
        prepare_attempt(request, denied, now=100, expires_at=200)
    with pytest.raises(AttemptDenied, match="authorization_denied"):
        claim_attempt(
            prepared(request), denied, expected_generation=0,
            lease_id="worker-a", now=101, lease_seconds=20,
        )


@pytest.mark.parametrize("changes", [
    {"tenant": "tenant-b"}, {"issuer": "other"}, {"principal": "other"},
    {"membership_ref": 8}, {"customer_id": "cus_Other"}, {"price": "price_Other"},
])
def test_cross_association_approval_denied(changes):
    with pytest.raises(AttemptDenied, match="authorization_denied"):
        prepare_attempt(frozen(), approval(frozen(**changes)), now=100, expires_at=200)


def test_prepare_replay_preserves_state_and_original_deadlines():
    old = dispatch()
    candidate = prepare_attempt(frozen(), approval(), now=150, expires_at=250)
    assert resolve_prepare(candidate, existing=old, tenant_slot=old) is old
    assert old.prepare_expires_at == 200
    assert old.generation == 1


@pytest.mark.parametrize("changes", [
    {"tenant": "tenant-b"}, {"principal": "subject-b"}, {"membership_ref": 8},
    {"customer_id": "cus_Other"}, {"price": "price_Other"},
    {"adapter_version": "checkout-v2"},
])
def test_same_attempt_changed_owner_or_parameters_conflicts(changes):
    with pytest.raises(AttemptDenied, match="attempt_conflict"):
        resolve_prepare(prepared(frozen(**changes)), existing=prepared(), tenant_slot=prepared())


@pytest.mark.parametrize("occupant", [
    prepared, dispatch, lambda: attach(),
    lambda: mark_unknown(dispatch(), expected_generation=1, now=105),
    lambda: quarantine_attempt(prepared(), expected_generation=0, now=101),
])
def test_new_attempt_cannot_bypass_unresolved_tenant_purchase(occupant):
    candidate = prepared(frozen(attempt="2" * 32, account="acct_OtherSandbox"))
    with pytest.raises(AttemptDenied, match="tenant_purchase_unresolved"):
        resolve_prepare(candidate, existing=None, tenant_slot=occupant())


def test_unrelated_tenant_snapshot_is_not_authoritative():
    with pytest.raises(AttemptDenied, match="invalid_tenant_slot"):
        resolve_prepare(prepared(), existing=None, tenant_slot=prepared(frozen(tenant="tenant-b")))


def test_new_attempt_after_proven_unsent_expiry():
    expired = expire_unsent(prepared(), expected_generation=0, now=200)
    assert expired.state is State.EXPIRED_UNSENT
    assert not expired.holds_tenant_slot
    candidate = prepared(frozen(attempt="2" * 32))
    assert resolve_prepare(candidate, existing=None, tenant_slot=expired) is candidate
    assert resolve_prepare(prepared(), existing=expired, tenant_slot=None) is expired


def test_unknown_never_redispatches_or_expires_unsent():
    unknown = mark_unknown(dispatch(), expected_generation=1, now=122)
    assert unknown.state is State.UNKNOWN and unknown.holds_tenant_slot
    assert unknown.lease_id is None
    with pytest.raises(AttemptDenied, match="creation_not_claimable"):
        claim_attempt(
            unknown, approval(), expected_generation=2, lease_id="worker-b",
            now=123, lease_seconds=20,
        )
    with pytest.raises(AttemptDenied, match="not_proven_unsent"):
        expire_unsent(unknown, expected_generation=2, now=500)


def test_recovery_fences_original_worker_and_only_reconciles():
    original = dispatch()
    recovered = claim_recovery(
        original, expected_generation=1, lease_id="worker-b", now=121, lease_seconds=20,
    )
    assert recovered.state is State.UNKNOWN
    assert recovered.generation == 2 and recovered.holds_tenant_slot
    fresh = session(observed_at=122)
    with pytest.raises(AttemptDenied, match="stale_generation"):
        attach(recovered, fresh, expected_generation=1, lease_id="worker-a", now=123)
    with pytest.raises(AttemptDenied, match="stale_lease"):
        attach(recovered, fresh, lease_id="worker-a", now=123)
    attached = attach(recovered, fresh, lease_id="worker-b", now=123)
    assert attached.state is State.SESSION_ATTACHED
    assert attached.generation == 3 and attached.holds_tenant_slot


@pytest.mark.parametrize("now", [121, 122])
def test_expired_creation_lease_cannot_confirm(now):
    with pytest.raises(AttemptDenied, match="stale_lease"):
        attach(dispatch(), session(observed_at=now), now=now)


def test_live_lease_not_stolen_and_clocks_never_roll_back():
    with pytest.raises(AttemptDenied, match="lease_busy"):
        claim_recovery(dispatch(), expected_generation=1, lease_id="worker-b", now=120, lease_seconds=20)
    with pytest.raises(AttemptDenied, match="clock_rollback"):
        mark_unknown(dispatch(), expected_generation=1, now=100)


@pytest.mark.parametrize("evidence", [
    None, {}, {"session_id": "cs_test_Forged", "verified": True},
    session(frozen(tenant="tenant-b")), session(frozen(customer_id="cus_Other")),
    session(frozen(price="price_Other")), session(frozen(membership_ref=8)),
    session(observed_at=100), session(observed_at=104),
])
def test_forged_or_unassociated_session_claims_denied(evidence):
    with pytest.raises(AttemptDenied, match="session_association_denied"):
        attach(dispatch(), evidence=evidence if evidence is not None else {})


@pytest.mark.parametrize("changes", [
    {"session_id": "cs_live_Forged"}, {"session_id": "cs_test_"},
    {"observed_at": True}, {"expires_at": float("inf")}, {"status": "open"},
    {"status": SessionStatus.EXPIRED},
    {"subscription_id": "sub_Forged"}, {"handoff_record_id": "handoff"},
    {"status": SessionStatus.COMPLETE},
])
def test_invalid_session_evidence(changes):
    with pytest.raises(AttemptDenied, match="invalid_session_evidence"):
        session(**changes)


def test_attached_session_is_not_payment_or_closure():
    attached = attach()
    with pytest.raises(AttemptDenied, match="unverified_closure"):
        close_verified(attached, expected_generation=2, now=104)
    complete = attach(evidence=session(status=SessionStatus.COMPLETE, subscription_id="sub_Synthetic"))
    with pytest.raises(AttemptDenied, match="unverified_closure"):
        close_verified(complete, expected_generation=2, now=104)


@pytest.mark.parametrize("evidence", [
    session(observed_at=300, status=SessionStatus.EXPIRED),
    session(observed_at=300, status=SessionStatus.COMPLETE,
            subscription_id="sub_Synthetic", handoff_record_id="durable-handoff-1"),
])
def test_only_verified_closure_or_durable_subscription_handoff_releases_slot(evidence):
    unknown = mark_unknown(dispatch(), expected_generation=1, now=122)
    recovery = claim_recovery(
        unknown, expected_generation=2, lease_id="recovery", now=299, lease_seconds=20,
    )
    attached = attach(recovery, evidence, lease_id="recovery", now=301)
    closed = close_verified(attached, expected_generation=4, now=302)
    assert closed.state is State.CLOSED_VERIFIED and not closed.holds_tenant_slot
    assert closed.request == prepared().request
    assert closed.session == evidence
    assert resolve_prepare(
        prepared(frozen(attempt="2" * 32)), existing=None, tenant_slot=closed,
    ).state is State.PREPARED


def test_conflicting_session_cannot_replace_attached_identity():
    recovery = claim_recovery(
        attach(), expected_generation=2, lease_id="recovery", now=104, lease_seconds=20,
    )
    with pytest.raises(AttemptDenied, match="session_conflict"):
        attach(recovery, session(session_id="cs_test_Other", observed_at=105), now=106)


def test_exact_session_confirmation_replay_is_noop_and_never_refreshes():
    attached = attach()
    assert confirm_session(
        attached, attached.session, expected_generation=2, lease_id="old-worker", now=110,
    ) is attached
    with pytest.raises(AttemptDenied, match="stale_generation"):
        confirm_session(
            attached, attached.session, expected_generation=1, lease_id="worker-a", now=110,
        )
    with pytest.raises(AttemptDenied, match="stale_lease"):
        confirm_session(
            attached, session(observed_at=109), expected_generation=2,
            lease_id="worker-a", now=110,
        )


@pytest.mark.parametrize("changes", [
    {"status": SessionStatus.OPEN, "subscription_id": None, "handoff_record_id": None},
    {"subscription_id": "sub_Other"}, {"handoff_record_id": "different-handoff"},
    {"handoff_record_id": None}, {"expires_at": 301},
])
def test_established_terminal_session_and_handoff_cannot_be_rewritten(changes):
    complete = session(
        status=SessionStatus.COMPLETE, subscription_id="sub_Synthetic",
        handoff_record_id="handoff-1",
    )
    attached = attach(evidence=complete)
    recovery = claim_recovery(
        attached, expected_generation=2, lease_id="recovery", now=104, lease_seconds=20,
    )
    with pytest.raises(AttemptDenied, match="session_conflict"):
        attach(recovery, replace(complete, observed_at=105, **changes), now=106)
    with pytest.raises(AttemptDenied, match="invalid_transition"):
        close_verified(recovery, expected_generation=3, now=106)


def test_evidence_refresh_preserves_identity_and_requires_new_lease():
    attached = attach()
    recovery = claim_recovery(
        attached, expected_generation=2, lease_id="recovery", now=300, lease_seconds=20,
    )
    evidence = session(status=SessionStatus.EXPIRED, observed_at=301)
    refreshed = attach(recovery, evidence, now=302)
    assert refreshed.session == evidence
    assert refreshed.request is attached.request
    assert refreshed.created_at == attached.created_at
    assert refreshed.prepare_expires_at == attached.prepare_expires_at
    assert refreshed.generation == 4
    assert not close_verified(refreshed, expected_generation=4, now=303).holds_tenant_slot


def test_recovery_records_created_purchase_even_after_customer_revocation():
    attached = attach()
    with pytest.raises(AttemptDenied, match="authorization_denied"):
        claim_attempt(
            prepared(), approval(membership_active=False), expected_generation=0,
            lease_id="new-create", now=104, lease_seconds=20,
        )
    # Recovery never consumes an approval snapshot and cannot issue another create.
    recovery = claim_recovery(
        attached, expected_generation=2, lease_id="recovery", now=300, lease_seconds=20,
    )
    confirmed = attach(
        recovery, session(status=SessionStatus.EXPIRED, observed_at=301), now=302,
    )
    assert confirmed.holds_tenant_slot


def test_closed_verified_cannot_restart_or_be_marked_unknown():
    complete = attach(evidence=session(
        status=SessionStatus.COMPLETE, subscription_id="sub_Synthetic",
        handoff_record_id="handoff-1",
    ))
    closed = close_verified(complete, expected_generation=2, now=104)
    for action in (mark_unknown, quarantine_attempt, expire_unsent):
        with pytest.raises(AttemptDenied):
            action(closed, expected_generation=3, now=105)
    with pytest.raises(AttemptDenied):
        claim_recovery(closed, expected_generation=3, lease_id="worker", now=105, lease_seconds=20)


@pytest.mark.parametrize("changes", [
    {"state": State.EXPIRED_UNSENT},
    {"state": State.CLOSED_VERIFIED},
    {"state": State.DISPATCHING},
    {"state": "unknown"},
    {"lease_id": "worker"},
    {"session": session()},
    {"created_at": True}, {"updated_at": 99}, {"prepare_expires_at": 100},
])
def test_impossible_record_shapes_rejected(changes):
    with pytest.raises(AttemptDenied):
        replace(prepared(), **changes)


def test_ambiguous_dispatch_candidate_retains_same_identity_and_slot():
    before = dispatch()
    after = mark_unknown(before, expected_generation=1, now=105)
    assert after.request is before.request
    assert after.request.intent.idempotency_key == before.request.intent.idempotency_key
    assert after.holds_tenant_slot and after.state is State.UNKNOWN
    assert before.state is State.DISPATCHING  # Only a candidate, no durable update.


def test_recovery_write_must_match_allowed_candidate_and_preserve_binding():
    before = dispatch()
    unknown = mark_unknown(before, expected_generation=1, now=105)
    assert validate_recovery(before, unknown) is unknown
    with pytest.raises(AttemptDenied, match="immutable_attempt_conflict"):
        validate_recovery(before, replace(unknown, request=frozen(tenant="tenant-b")))
    with pytest.raises(AttemptDenied, match="immutable_attempt_conflict"):
        validate_recovery(before, replace(unknown, prepare_expires_at=300))
    with pytest.raises(AttemptDenied, match="immutable_attempt_conflict"):
        validate_recovery(before, replace(unknown, created_at=99))
    with pytest.raises(AttemptDenied, match="invalid_recovery"):
        validate_recovery(before, replace(unknown, generation=1))
    with pytest.raises(AttemptDenied, match="invalid_recovery"):
        validate_recovery(before, replace(unknown, session=session()))
    with pytest.raises(AttemptDenied):
        validate_recovery(before, replace(before, state=State.PREPARED,
                                          lease_id=None, lease_expires_at=None))
    with pytest.raises(AttemptDenied, match="not_proven_unsent"):
        validate_recovery(before, replace(unknown, state=State.EXPIRED_UNSENT, updated_at=200))


@pytest.mark.parametrize("operation", [
    lambda r: mark_unknown(r, expected_generation=r.generation, now=122),
    lambda r: quarantine_attempt(r, expected_generation=r.generation, now=122),
    lambda r: claim_recovery(
        r, expected_generation=r.generation, lease_id="recovery", now=122, lease_seconds=20,
    ),
])
def test_valid_recovery_variants_are_explicitly_checked(operation):
    before = dispatch()
    after = operation(before)
    assert validate_recovery(before, after) is after


def test_unsent_expiry_and_verified_closure_recovery_validation():
    before = prepared()
    expired = expire_unsent(before, expected_generation=0, now=200)
    assert validate_recovery(before, expired) is expired
    attached = attach(evidence=session(
        status=SessionStatus.COMPLETE, subscription_id="sub_Synthetic",
        handoff_record_id="handoff-1",
    ))
    closed = close_verified(attached, expected_generation=2, now=104)
    assert validate_recovery(attached, closed) is closed


@pytest.mark.parametrize("generation", [True, False, -1, 1.0, MAX_GENERATION + 1])
def test_invalid_record_generation(generation):
    with pytest.raises(AttemptDenied, match="invalid_attempt"):
        replace(prepared(), generation=generation)


def test_generation_boundary_never_returns_invalid_or_wraps():
    record = replace(prepared(), generation=MAX_GENERATION - 1)
    last = claim_attempt(
        record, approval(), expected_generation=MAX_GENERATION - 1,
        lease_id="worker", now=101, lease_seconds=20,
    )
    assert last.generation == MAX_GENERATION and last.holds_tenant_slot
    with pytest.raises(AttemptDenied, match="generation_exhausted"):
        mark_unknown(last, expected_generation=MAX_GENERATION, now=102)
    with pytest.raises(AttemptDenied, match="generation_exhausted"):
        quarantine_attempt(last, expected_generation=MAX_GENERATION, now=102)


@pytest.mark.parametrize("record,operation", [
    (prepared(), lambda r: claim_attempt(
        r, approval(), expected_generation=MAX_GENERATION,
        lease_id="worker", now=101, lease_seconds=20,
    )),
    (prepared(), lambda r: expire_unsent(r, expected_generation=MAX_GENERATION, now=200)),
    (dispatch(), lambda r: confirm_session(
        r, session(), expected_generation=MAX_GENERATION, lease_id="worker-a", now=103,
    )),
    (dispatch(), lambda r: claim_recovery(
        r, expected_generation=MAX_GENERATION, lease_id="recovery", now=122, lease_seconds=20,
    )),
    (attach(evidence=session(
        status=SessionStatus.COMPLETE, subscription_id="sub_Synthetic",
        handoff_record_id="handoff-1",
    )), lambda r: close_verified(r, expected_generation=MAX_GENERATION, now=104)),
])
def test_all_remaining_changing_operations_deny_generation_exhaustion(record, operation):
    exhausted = replace(record, generation=MAX_GENERATION)
    with pytest.raises(AttemptDenied, match="generation_exhausted"):
        operation(exhausted)
    assert exhausted.generation == MAX_GENERATION and exhausted.holds_tenant_slot


@pytest.mark.parametrize("value", [True, -1, 0, MAX_GENERATION + 1])
def test_stale_or_invalid_expected_generation(value):
    with pytest.raises(AttemptDenied, match="stale_generation"):
        mark_unknown(dispatch(), expected_generation=value, now=102)


@pytest.mark.parametrize("changes", [
    {"lease_seconds": True}, {"lease_seconds": 0}, {"lease_seconds": 301},
    {"lease_id": "../x"}, {"lease_id": ""}, {"now": True},
    {"now": 200}, {"now": -1},
])
def test_claim_bounds(changes):
    with pytest.raises(AttemptDenied):
        claim_attempt(prepared(), approval(), **{
            "expected_generation": 0, "lease_id": "worker", "now": 101,
            "lease_seconds": 20, **changes,
        })


@pytest.mark.parametrize("terminal", [
    lambda: expire_unsent(prepared(), expected_generation=0, now=200),
    lambda: quarantine_attempt(prepared(), expected_generation=0, now=101),
])
def test_terminal_and_quarantined_records_cannot_restart(terminal):
    record = terminal()
    with pytest.raises(AttemptDenied):
        claim_attempt(
            record, approval(), expected_generation=record.generation,
            lease_id="restart", now=201, lease_seconds=20,
        )
    with pytest.raises(AttemptDenied):
        claim_recovery(
            record, expected_generation=record.generation,
            lease_id="restart", now=201, lease_seconds=20,
        )


def test_unknown_storage_contract_is_explicit_and_has_no_backend():
    assert issubclass(AttemptCommitUnknown, AttemptStorageUnavailable)
    with pytest.raises(TypeError):
        CheckoutAttemptStore()
    assert set(State) == {
        State.PREPARED, State.DISPATCHING, State.SESSION_ATTACHED, State.UNKNOWN,
        State.QUARANTINED, State.EXPIRED_UNSENT, State.CLOSED_VERIFIED,
    }
