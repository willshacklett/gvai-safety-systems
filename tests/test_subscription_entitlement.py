from dataclasses import FrozenInstanceError, replace

import pytest

from gvai.identity import INTERNAL_TENANT_ID
from gvai.subscription_entitlement import (
    EntitlementDecision,
    EntitlementReason as Reason,
    EntitlementState,
    EventDisposition as Disposition,
    PaidInvoice,
    StripeEventType as EventType,
    SubscriptionAssociation,
    SubscriptionEvidence,
    SubscriptionStatus as Status,
    apply_entitlement_evidence,
    evaluate_entitlement,
    suspend_entitlement,
)


ASSOCIATION = SubscriptionAssociation(
    account_id="account-a",
    customer_id="cus-a",
    tenant_id="tenant-a",
    subscription_id="sub-a",
    price_id="price-advisory-monthly",
)
TTL = 100


def invoice(invoice_id="invoice-initial", start=100, end=200, **changes):
    return replace(PaidInvoice(invoice_id, ASSOCIATION, start, end, True), **changes)


def evidence(
    event_id="event-initial",
    event_type=EventType.INVOICE_PAID,
    revision=1,
    observed_at=100,
    status=Status.ACTIVE,
    **changes,
):
    return replace(
        SubscriptionEvidence(
            event_id=event_id,
            event_type=event_type,
            association=ASSOCIATION,
            revision=revision,
            observed_at=observed_at,
            status=status,
            certain=True,
            invoice=invoice() if event_type is EventType.INVOICE_PAID else None,
        ),
        **changes,
    )


def apply(state, event, now=100):
    return apply_entitlement_evidence(
        state, event, now=now, max_evidence_age=TTL
    )


def decide(state, now=100):
    return evaluate_entitlement(state, now=now, max_evidence_age=TTL)


def paid_state():
    return apply(EntitlementState(ASSOCIATION), evidence()).state


@pytest.mark.parametrize(
    "event_type,status,expected",
    [
        (EventType.INVOICE_PAID, Status.ACTIVE, Reason.PAID_ACCESS),
        (EventType.CHECKOUT_COMPLETED, Status.ACTIVE, Reason.NO_VERIFIED_PAYMENT),
        (EventType.SUBSCRIPTION_CREATED, Status.INCOMPLETE, Reason.INACTIVE_SUBSCRIPTION),
        (EventType.INVOICE_PAYMENT_FAILED, Status.INCOMPLETE, Reason.INACTIVE_SUBSCRIPTION),
        (EventType.INVOICE_PAYMENT_ACTION_REQUIRED, Status.INCOMPLETE, Reason.INACTIVE_SUBSCRIPTION),
        (EventType.SUBSCRIPTION_UPDATED, Status.ACTIVE, Reason.NO_VERIFIED_PAYMENT),
        (EventType.SUBSCRIPTION_DELETED, Status.CANCELED, Reason.TERMINAL_CANCELLATION),
    ],
)
def test_initial_subscription_cases(event_type, status, expected):
    result = apply(
        EntitlementState(ASSOCIATION), evidence(event_type=event_type, status=status)
    )
    assert result.disposition is Disposition.APPLIED
    assert result.decision.reason is expected
    assert result.decision.allowed is (expected is Reason.PAID_ACCESS)
    assert result.decision.access_until == (200 if result.decision.allowed else None)


@pytest.mark.parametrize("reason", list(Reason))
def test_only_paid_access_decisions_allow(reason):
    decision = EntitlementDecision(reason)
    assert decision.allowed is (reason is Reason.PAID_ACCESS)
    assert bool(decision) is decision.allowed


def test_successful_renewal_extends_contiguous_paid_coverage_without_mutation():
    state = paid_state()
    renewal = evidence(
        "event-renewal", revision=2, observed_at=150,
        invoice=invoice("invoice-renewal", 200, 300),
    )
    result = apply(state, renewal, now=150)
    assert result.decision.allowed
    assert result.decision.access_until == 250  # Evidence freshness is also a ceiling.
    assert decide(result.state, now=210).allowed
    assert len(result.state.paid_invoices) == 2
    assert state.paid_invoices == (invoice(),)
    assert state.latest_evidence == evidence()
    assert result == apply(state, renewal, now=150)


@pytest.mark.parametrize("different_event", [False, True])
def test_duplicate_event_or_invoice_never_extends_payment(different_event):
    state = paid_state()
    event = evidence()
    if different_event:
        event = replace(event, event_id="event-invoice-copy", revision=2, observed_at=110)
    result = apply(state, event, now=110)
    assert result.disposition is (
        Disposition.APPLIED if different_event else Disposition.DUPLICATE
    )
    assert result.state.paid_invoices == state.paid_invoices
    assert result.decision.access_until == 200
    if not different_event:
        assert result.state == state
        assert result.state.latest_evidence.observed_at == 100


def test_duplicate_delivery_cannot_refresh_stale_evidence():
    result = apply(paid_state(), evidence(), now=200)
    assert result.disposition is Disposition.DUPLICATE
    assert result.decision.reason is Reason.STALE_EVIDENCE
    assert result.decision.allowed is False


@pytest.mark.parametrize("cancel_first", [False, True])
def test_terminal_cancellation_wins_in_both_delivery_orders(cancel_first):
    payment = evidence()
    cancellation = evidence(
        "event-canceled", EventType.SUBSCRIPTION_DELETED,
        revision=2, observed_at=110, status=Status.CANCELED,
    )
    events = (cancellation, payment) if cancel_first else (payment, cancellation)
    state = EntitlementState(ASSOCIATION)
    for event in events:
        state = apply(state, event, now=110).state
    assert state.terminal_canceled
    assert decide(state, now=110).reason is Reason.TERMINAL_CANCELLATION
    newer_payment = evidence(
        "event-late-payment", revision=3, observed_at=120,
        invoice=invoice("invoice-late", 100, 400),
    )
    result = apply(state, newer_payment, now=120)
    assert result.decision.reason is Reason.TERMINAL_CANCELLATION
    assert result.state.paid_invoices == state.paid_invoices


def test_verified_terminal_cancellation_is_not_discarded_as_an_old_snapshot():
    state = apply(
        paid_state(),
        evidence("event-newer", EventType.SUBSCRIPTION_UPDATED, 3, 120),
        now=120,
    ).state
    cancellation = evidence(
        "event-old-cancel", EventType.SUBSCRIPTION_DELETED, 2, 110, Status.CANCELED
    )
    result = apply(state, cancellation, now=120)
    assert result.state.terminal_canceled
    assert result.decision.reason is Reason.TERMINAL_CANCELLATION


@pytest.mark.parametrize("paid_first", [False, True])
def test_initial_payment_and_active_snapshot_can_arrive_in_either_order(paid_first):
    payment = evidence(status=Status.INCOMPLETE)
    active = evidence("event-active", EventType.SUBSCRIPTION_UPDATED, 2, 110)
    if not paid_first:
        # A later reconciliation of an older invoice has a NEW fenced revision.
        payment = replace(payment, revision=3, observed_at=120, status=Status.ACTIVE)
    events = (payment, active) if paid_first else (active, payment)
    state = EntitlementState(ASSOCIATION)
    for event in events:
        state = apply(state, event, now=120).state
    assert decide(state, now=120).allowed
    assert len(state.paid_invoices) == 1


@pytest.mark.parametrize("now,expected", [
    (149, Reason.PAID_ACCESS),
    (150, Reason.SCHEDULED_CANCELLATION),
    (151, Reason.SCHEDULED_CANCELLATION),
])
def test_period_end_cancellation_uses_exclusive_effective_boundary(now, expected):
    state = apply(
        paid_state(),
        evidence("event-scheduled", EventType.SUBSCRIPTION_UPDATED, 2, 110, cancel_at=150),
        now=110,
    ).state
    decision = decide(state, now=now)
    assert decision.reason is expected
    assert decision.access_until == (150 if decision.allowed else None)


def test_new_reconciliation_can_reverse_scheduled_but_not_terminal_cancellation():
    state = apply(
        paid_state(),
        evidence("event-scheduled", EventType.SUBSCRIPTION_UPDATED, 2, 110, cancel_at=150),
        now=110,
    ).state
    result = apply(
        state, evidence("event-unscheduled", EventType.SUBSCRIPTION_UPDATED, 3, 120),
        now=120,
    )
    assert result.decision.allowed
    assert result.decision.access_until == 200


@pytest.mark.parametrize("event_type", [
    EventType.INVOICE_PAYMENT_FAILED, EventType.INVOICE_PAYMENT_ACTION_REQUIRED,
])
def test_failed_or_action_required_payment_preserves_only_existing_paid_interval(event_type):
    state = apply(
        paid_state(), evidence("event-failed", event_type, 2, 150), now=150
    ).state
    assert state.paid_invoices == (invoice(),)
    assert decide(state, now=199).allowed
    assert decide(state, now=200).reason is Reason.OUTSIDE_PAID_INTERVAL


@pytest.mark.parametrize("status", [
    Status.INCOMPLETE, Status.INCOMPLETE_EXPIRED, Status.TRIALING,
    Status.PAST_DUE, Status.UNPAID, Status.PAUSED,
])
def test_nonactive_subscription_does_not_grant_prepaid_access(status):
    result = apply(
        paid_state(),
        evidence("event-inactive", EventType.SUBSCRIPTION_UPDATED, 2, 110, status),
        now=110,
    )
    assert result.decision.reason is Reason.INACTIVE_SUBSCRIPTION


@pytest.mark.parametrize("now,expected", [
    (99, Reason.OUTSIDE_PAID_INTERVAL),
    (100, Reason.PAID_ACCESS),
    (199, Reason.PAID_ACCESS),
    (200, Reason.OUTSIDE_PAID_INTERVAL),
])
def test_paid_interval_boundaries(now, expected):
    state = apply(
        EntitlementState(ASSOCIATION),
        evidence(observed_at=90),
        now=100,
    ).state
    decision = evaluate_entitlement(state, now=now, max_evidence_age=1000)
    assert decision.reason is expected


def test_future_renewal_does_not_bridge_unpaid_gap():
    state = apply(
        paid_state(),
        evidence(
            "event-future", revision=2, observed_at=150,
            invoice=invoice("invoice-gap", 250, 350),
        ),
        now=150,
    ).state
    assert decide(state, now=199).access_until == 200
    assert decide(state, now=210).reason is Reason.OUTSIDE_PAID_INTERVAL
    refreshed = apply(
        state, evidence("event-refresh", EventType.SUBSCRIPTION_UPDATED, 3, 250),
        now=250,
    ).state
    assert decide(refreshed, now=250).allowed


@pytest.mark.parametrize("suspend_first", [False, True])
def test_operator_suspension_is_latched_and_payment_cannot_remove_it(suspend_first):
    state = EntitlementState(ASSOCIATION)
    if suspend_first:
        state = suspend_entitlement(state)
    state = apply(state, evidence()).state
    if not suspend_first:
        state = suspend_entitlement(state)
    result = apply(
        state,
        evidence("event-renewal", revision=2, observed_at=110, invoice=invoice("renew", 200, 300)),
        now=110,
    )
    assert result.state.operator_suspended
    assert result.decision.reason is Reason.OPERATOR_SUSPENDED
    assert suspend_entitlement(state) == state


def test_operator_suspension_takes_precedence_over_cancellation_and_staleness():
    state = apply(
        EntitlementState(ASSOCIATION),
        evidence(event_type=EventType.SUBSCRIPTION_DELETED, status=Status.CANCELED),
    ).state
    assert decide(suspend_entitlement(state), now=1000).reason is Reason.OPERATOR_SUSPENDED


@pytest.mark.parametrize("certain", [False, True])
def test_stale_cancellation_is_deny_only_and_uncertain_cancellation_is_not_terminal(certain):
    cancellation = evidence(
        "event-cancel", EventType.SUBSCRIPTION_DELETED, 2, 110, Status.CANCELED,
        certain=certain,
    )
    result = apply(paid_state(), cancellation, now=250)
    assert not result.decision.allowed
    assert result.state.terminal_canceled is certain
    assert result.state.paid_invoices == (invoice(),)


@pytest.mark.parametrize("field", [
    "account_id", "customer_id", "tenant_id", "subscription_id", "price_id",
])
@pytest.mark.parametrize("invoice_association", [False, True])
def test_mismatched_event_or_invoice_association_denies_without_mutating_state(
    field, invoice_association
):
    state = paid_state()
    wrong = replace(ASSOCIATION, **{field: "different"})
    event = evidence("event-wrong", revision=2, observed_at=110)
    event = replace(
        event,
        **({"invoice": replace(event.invoice, association=wrong)}
           if invoice_association else {"association": wrong}),
    )
    result = apply(state, event, now=110)
    assert result.disposition is Disposition.REJECTED
    assert result.decision.reason is Reason.INVALID_ASSOCIATION
    assert not result.decision.allowed
    assert result.state == state


@pytest.mark.parametrize("now,reason", [
    (99, Reason.FUTURE_EVIDENCE),
    (100, Reason.PAID_ACCESS),
    (199, Reason.PAID_ACCESS),
    (200, Reason.STALE_EVIDENCE),
])
def test_evidence_freshness_boundary(now, reason):
    state = apply(
        EntitlementState(ASSOCIATION),
        evidence(invoice=invoice(end=400)),
    ).state
    assert decide(state, now=now).reason is reason


@pytest.mark.parametrize("uncertainty", ["snapshot", "payment"])
def test_uncertain_evidence_blocks_until_newer_certain_reconciliation(uncertainty):
    event = evidence("event-uncertain", revision=2, observed_at=110)
    event = replace(
        event,
        **({"certain": False} if uncertainty == "snapshot"
           else {"invoice": replace(event.invoice, verified=False)}),
    )
    result = apply(paid_state(), event, now=110)
    assert result.decision.reason is Reason.UNCERTAIN_EVIDENCE
    assert result.state.uncertain
    assert decide(result.state, now=110).reason is Reason.UNCERTAIN_EVIDENCE
    assert not apply(result.state, evidence(), now=110).decision.allowed
    refreshed = apply(
        result.state, evidence("event-confirmed", EventType.SUBSCRIPTION_UPDATED, 3, 120),
        now=120,
    )
    assert refreshed.decision.allowed
    assert not refreshed.state.uncertain


@pytest.mark.parametrize("changes", [
    {"revision": 0, "observed_at": 110},
    {"revision": 2, "observed_at": 99},
])
def test_outdated_snapshots_cannot_replace_current_state(changes):
    state = paid_state()
    event = evidence("event-outdated", **changes)
    result = apply(state, event, now=110)
    assert result.disposition is Disposition.REJECTED
    assert result.decision.reason is Reason.OUTDATED_EVIDENCE
    assert result.state == state


@pytest.mark.parametrize("conflict", ["event-id", "revision", "invoice-id"])
def test_conflicting_reuse_fails_closed_and_blocks_persisted_state(conflict):
    event = evidence("event-conflict", revision=2, observed_at=110)
    if conflict == "event-id":
        event = replace(event, event_id="event-initial")
    elif conflict == "revision":
        event = replace(event, revision=1)
    else:
        event = replace(event, invoice=invoice(end=400))
    result = apply(paid_state(), event, now=110)
    assert result.disposition is Disposition.REJECTED
    assert result.decision.reason is Reason.CONFLICTING_EVIDENCE
    assert result.state.uncertain
    assert not decide(result.state, now=110).allowed


def test_duplicates_of_earlier_events_cannot_clear_conflict_or_renew_freshness():
    state = apply(
        paid_state(),
        evidence("event-renewal", revision=2, observed_at=110,
                 invoice=invoice("renew", 200, 300)),
        now=110,
    ).state
    conflict = replace(evidence(), observed_at=120)
    conflicted = apply(state, conflict, now=120).state
    result = apply(conflicted, evidence(), now=120)
    assert result.disposition is Disposition.DUPLICATE
    assert result.state == conflicted
    assert result.decision.reason is Reason.UNCERTAIN_EVIDENCE


@pytest.mark.parametrize("event", [
    evidence(observed_at=101),
    evidence(observed_at=0),
    evidence(certain=False),
    evidence(invoice=invoice(verified=False)),
])
def test_future_stale_and_unverified_evidence_never_add_paid_coverage(event):
    result = apply(EntitlementState(ASSOCIATION), event, now=100)
    assert not result.decision.allowed
    assert result.state.paid_invoices == ()


@pytest.mark.parametrize("periods,now,expected_end", [
    (((100, 200), (150, 300)), 175, 300),
    (((100, 200), (200, 300)), 200, 300),
    (((100, 200), (201, 300)), 200, None),
    (((200, 300), (100, 200)), 150, 300),
    (((100, 150), (100, 200)), 125, 200),
])
def test_paid_interval_union_never_bridges_a_gap(periods, now, expected_end):
    state = EntitlementState(ASSOCIATION)
    for index, (start, end) in enumerate(periods):
        state = apply(
            state,
            evidence(f"event-{index}", revision=index, observed_at=100,
                     invoice=invoice(f"invoice-{index}", start, end)),
            now=100,
        ).state
    decision = evaluate_entitlement(state, now=now, max_evidence_age=1000)
    assert decision.allowed is (expected_end is not None)
    assert decision.access_until == expected_end


def test_no_evidence_and_unverified_initial_invoice_never_grant():
    state = EntitlementState(ASSOCIATION)
    assert decide(state).reason is Reason.MISSING_EVIDENCE
    result = apply(state, evidence(invoice=invoice(verified=False)))
    assert not result.decision.allowed
    assert result.state.paid_invoices == ()


@pytest.mark.parametrize("event", [
    evidence(certain=False),
    evidence(invoice=invoice(verified=False)),
])
def test_direct_assessment_checks_evidence_certainty_not_only_state_flag(event):
    state = EntitlementState(
        ASSOCIATION, processed_events=(event,), paid_invoices=(invoice(),)
    )
    assert decide(state).reason is Reason.UNCERTAIN_EVIDENCE


@pytest.mark.parametrize("field,value", [
    ("tenant_id", INTERNAL_TENANT_ID),
    ("tenant_id", ""),
    ("account_id", None),
    ("customer_id", "bad/customer"),
    ("price_id", "x" * 129),
    ("subscription_id", b"sub-a"),
])
def test_invalid_association_values_raise_explicit_error(field, value):
    with pytest.raises(ValueError, match="Invalid subscription association"):
        replace(ASSOCIATION, **{field: value})


@pytest.mark.parametrize("changes", [
    {"revision": True}, {"revision": -1}, {"revision": 1.0},
    {"observed_at": float("nan")}, {"observed_at": -1},
    {"certain": "yes"}, {"status": "active"}, {"event_type": "invoice.paid"},
    {"event_id": ""}, {"association": None}, {"cancel_at": True},
    {"invoice": None},
])
def test_invalid_normalized_evidence_raises_explicit_error(changes):
    with pytest.raises(ValueError, match="Invalid subscription evidence"):
        replace(evidence(), **changes)


@pytest.mark.parametrize("event_type,status,paid_invoice", [
    (EventType.SUBSCRIPTION_DELETED, Status.ACTIVE, None),
    (EventType.CHECKOUT_COMPLETED, Status.ACTIVE, invoice()),
    (EventType.INVOICE_PAYMENT_FAILED, Status.ACTIVE, invoice()),
    (EventType.INVOICE_PAID, Status.ACTIVE, {}),
])
def test_incoherent_event_shape_is_rejected(event_type, status, paid_invoice):
    with pytest.raises(ValueError, match="Invalid subscription evidence"):
        replace(evidence(), event_type=event_type, status=status, invoice=paid_invoice)


@pytest.mark.parametrize("changes", [
    {"period_start": True}, {"period_start": -1}, {"period_end": 100},
    {"period_end": float("inf")}, {"verified": 1}, {"invoice_id": ""},
    {"association": None},
])
def test_invalid_invoice_values_raise_explicit_error(changes):
    with pytest.raises(ValueError, match="Invalid paid invoice"):
        replace(invoice(), **changes)


@pytest.mark.parametrize("kwargs", [
    {"now": True, "max_evidence_age": TTL},
    {"now": -1, "max_evidence_age": TTL},
    {"now": float("inf"), "max_evidence_age": TTL},
    {"now": 100, "max_evidence_age": 0},
    {"now": 100, "max_evidence_age": True},
])
def test_invalid_clock_or_freshness_configuration_raises_explicit_error(kwargs):
    with pytest.raises(ValueError, match="Invalid entitlement time"):
        evaluate_entitlement(paid_state(), **kwargs)
    with pytest.raises(ValueError, match="Invalid entitlement time"):
        apply_entitlement_evidence(paid_state(), evidence(), **kwargs)


@pytest.mark.parametrize("changes", [
    {"association": None}, {"operator_suspended": "false"},
    {"terminal_canceled": 0}, {"uncertain": None},
    {"processed_events": []}, {"processed_events": ({},)},
    {"paid_invoices": []}, {"paid_invoices": (invoice(verified=False),)},
])
def test_invalid_state_raises_explicit_error(changes):
    with pytest.raises(ValueError, match="Invalid entitlement state"):
        replace(paid_state(), **changes)


def test_input_and_output_records_are_immutable():
    state = paid_state()
    with pytest.raises(FrozenInstanceError):
        state.operator_suspended = False
    with pytest.raises(FrozenInstanceError):
        state.latest_evidence.status = Status.CANCELED
    with pytest.raises(FrozenInstanceError):
        state.paid_invoices[0].period_end = 1000


@pytest.mark.parametrize("revision,observed_at", [(0, 90), (1, 100), (2, 110)])
@pytest.mark.parametrize("now", [110, 250])
def test_canceled_subscription_update_latches_even_if_old_same_revision_or_stale(
    revision, observed_at, now
):
    state = paid_state()
    cancellation = evidence(
        "event-canceled-update", EventType.SUBSCRIPTION_UPDATED,
        revision, observed_at, Status.CANCELED,
    )
    result = apply(state, cancellation, now=now)
    assert result.disposition is Disposition.APPLIED
    assert result.state.terminal_canceled
    assert result.state.paid_invoices == state.paid_invoices
    assert result.decision.reason is Reason.TERMINAL_CANCELLATION
    assert result.decision.access_until is None
    assert decide(result.state, now=now).allowed is False
    assert not state.terminal_canceled


@pytest.mark.parametrize("cancel_event_type", [
    EventType.SUBSCRIPTION_UPDATED, EventType.SUBSCRIPTION_DELETED,
])
@pytest.mark.parametrize("payment_revision", [0, 2, 3])
@pytest.mark.parametrize("verified", [False, True])
def test_older_same_revision_and_newer_payments_cannot_reverse_terminal_cancellation(
    cancel_event_type, payment_revision, verified
):
    canceled = apply(
        paid_state(),
        evidence("event-cancel", cancel_event_type, 2, 110, Status.CANCELED),
        now=110,
    ).state
    payment = evidence(
        "event-payment-after-cancel", revision=payment_revision, observed_at=120,
        invoice=invoice("invoice-after-cancel", 100, 1000, verified=verified),
    )
    result = apply(canceled, payment, now=120)
    assert result.disposition is Disposition.REJECTED
    assert result.state == canceled
    assert result.decision.reason is Reason.TERMINAL_CANCELLATION
    assert result.decision.access_until is None
    assert decide(result.state, now=120).allowed is False


@pytest.mark.parametrize("now", [149, 150, 151])
@pytest.mark.parametrize("reuse_event_id", [False, True])
@pytest.mark.parametrize("cancel_at", [None, 300])
def test_same_revision_conflict_cannot_remove_or_extend_scheduled_cancellation(
    now, reuse_event_id, cancel_at
):
    scheduled = evidence(
        "event-scheduled", EventType.SUBSCRIPTION_UPDATED, 2, 110, cancel_at=150
    )
    state = apply(paid_state(), scheduled, now=110).state
    conflict = replace(
        scheduled,
        event_id=scheduled.event_id if reuse_event_id else "event-conflicting-schedule",
        cancel_at=cancel_at,
    )
    result = apply(state, conflict, now=now)
    assert result.disposition is Disposition.REJECTED
    assert result.decision.reason is Reason.CONFLICTING_EVIDENCE
    assert result.decision.access_until is None
    assert result.state.uncertain
    assert result.state.latest_evidence == scheduled
    assert result.state.latest_evidence.cancel_at == 150
    assert result.state.paid_invoices == state.paid_invoices
    assert decide(result.state, now=now).allowed is False
    replay = apply(result.state, scheduled, now=now)
    assert replay.disposition is Disposition.DUPLICATE
    assert replay.state == result.state
    assert replay.decision.allowed is False
    assert replay.decision.access_until is None


@pytest.mark.parametrize("first_stale", [False, True])
@pytest.mark.parametrize("removal_kind", ["stale", "uncertain", "same-revision"])
def test_newer_invalid_evidence_cannot_restore_access_by_removing_cancellation(
    first_stale, removal_kind
):
    state = apply(
        EntitlementState(ASSOCIATION),
        evidence(invoice=invoice(end=400)),
    ).state
    scheduled = apply(
        state,
        evidence("event-scheduled", EventType.SUBSCRIPTION_UPDATED, 2, 110, cancel_at=150),
        now=110,
    ).state
    uncertain = evidence(
        "event-first-removal", EventType.SUBSCRIPTION_UPDATED, 3,
        120 if first_stale else 220, certain=first_stale,
    )
    first = apply(scheduled, uncertain, now=220)
    assert first.state.uncertain
    assert first.decision.reason is (
        Reason.STALE_EVIDENCE if first_stale else Reason.UNCERTAIN_EVIDENCE
    )
    removal = evidence(
        "event-next-removal", EventType.SUBSCRIPTION_UPDATED,
        3 if removal_kind == "same-revision" else 4,
        130 if removal_kind == "stale" else 230,
        certain=removal_kind != "uncertain",
    )
    second = apply(first.state, removal, now=230)
    assert second.decision.allowed is False
    assert second.decision.access_until is None
    assert second.state.uncertain
    assert second.state.paid_invoices == scheduled.paid_invoices
    assert decide(second.state, now=230).allowed is False
    for duplicate in (uncertain, removal):
        replay = apply(second.state, duplicate, now=230)
        assert replay.decision.allowed is False
        assert replay.decision.access_until is None
        assert replay.state.paid_invoices == scheduled.paid_invoices
    confirmed_schedule = apply(
        second.state,
        evidence("event-confirmed-schedule", EventType.SUBSCRIPTION_UPDATED, 5, 240,
                 cancel_at=150),
        now=240,
    )
    assert not confirmed_schedule.state.uncertain
    assert confirmed_schedule.decision.reason is Reason.SCHEDULED_CANCELLATION
    assert confirmed_schedule.decision.access_until is None
    # Only a genuinely new, certain reconciliation may reverse a nonterminal schedule.
    confirmed_removal = apply(
        confirmed_schedule.state,
        evidence("event-confirmed-removal", EventType.SUBSCRIPTION_UPDATED, 6, 250),
        now=250,
    )
    assert not confirmed_removal.state.terminal_canceled
    assert confirmed_removal.decision.allowed is True
    assert confirmed_removal.decision.access_until == 350
    assert confirmed_removal.state.paid_invoices == scheduled.paid_invoices


@pytest.mark.parametrize("event_type", list(EventType))
@pytest.mark.parametrize("variant", ["fresh", "stale", "uncertain", "older"])
def test_operator_suspension_rejects_every_billing_event_without_state_changes(
    event_type, variant
):
    state = suspend_entitlement(paid_state())
    event = evidence(
        "event-after-suspension", event_type,
        0 if variant == "older" else 2,
        0 if variant == "stale" else 110,
        Status.CANCELED if event_type is EventType.SUBSCRIPTION_DELETED else Status.ACTIVE,
        certain=variant != "uncertain",
    )
    result = apply(state, event, now=120)
    assert result.disposition is Disposition.REJECTED
    assert result.state == state
    assert result.decision.reason is Reason.OPERATOR_SUSPENDED
    assert result.decision.access_until is None
    assert decide(result.state, now=120).reason is Reason.OPERATOR_SUSPENDED


@pytest.mark.parametrize("conflict", [False, True])
def test_duplicate_or_conflicting_payment_cannot_clear_operator_suspension(conflict):
    state = suspend_entitlement(paid_state())
    event = evidence()
    if conflict:
        event = replace(event, invoice=invoice(end=1000))
    result = apply(state, event, now=120)
    assert result.disposition is Disposition.REJECTED
    assert result.state == state
    assert result.decision.reason is Reason.OPERATOR_SUSPENDED
    assert result.decision.access_until is None


@pytest.mark.parametrize("kind", [
    "duplicate", "stale", "outdated", "same-revision", "event-conflict", "invoice-conflict",
])
def test_rejected_or_duplicate_payments_cannot_extend_access_or_paid_coverage(kind):
    state = apply(
        EntitlementState(ASSOCIATION),
        evidence(invoice=invoice(end=400)),
    ).state
    original = state.latest_evidence
    event = evidence(
        "event-extension", revision=2, observed_at=150,
        invoice=invoice("invoice-extension", 100, 1000),
    )
    now = 150
    if kind == "duplicate":
        event = original
    elif kind == "stale":
        event = replace(event, observed_at=120)
        now = 220
    elif kind == "outdated":
        event = replace(event, revision=0)
    elif kind == "same-revision":
        event = replace(event, revision=1)
    elif kind == "event-conflict":
        event = replace(event, event_id=original.event_id)
    else:
        event = replace(event, invoice=invoice(end=1000))
    result = apply(state, event, now=now)
    expected_disposition, expected_reason = {
        "duplicate": (Disposition.DUPLICATE, Reason.PAID_ACCESS),
        "stale": (Disposition.APPLIED, Reason.STALE_EVIDENCE),
        "outdated": (Disposition.REJECTED, Reason.OUTDATED_EVIDENCE),
        "same-revision": (Disposition.REJECTED, Reason.CONFLICTING_EVIDENCE),
        "event-conflict": (Disposition.REJECTED, Reason.CONFLICTING_EVIDENCE),
        "invoice-conflict": (Disposition.REJECTED, Reason.CONFLICTING_EVIDENCE),
    }[kind]
    assert result.disposition is expected_disposition
    assert result.decision.reason is expected_reason
    assert result.state.paid_invoices == state.paid_invoices
    assert result.decision.access_until == (200 if kind == "duplicate" else None)
    retained = decide(result.state, now=now)
    assert retained.access_until == (200 if kind in ("duplicate", "outdated") else None)
    assert decide(result.state, now=400).allowed is False
