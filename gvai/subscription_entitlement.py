from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum

from gvai.commercial_identity import _valid_customer_tenant, _valid_identifier


class StripeEventType(str, Enum):
    CHECKOUT_COMPLETED = "checkout.session.completed"
    SUBSCRIPTION_CREATED = "customer.subscription.created"
    SUBSCRIPTION_UPDATED = "customer.subscription.updated"
    SUBSCRIPTION_DELETED = "customer.subscription.deleted"
    INVOICE_PAID = "invoice.paid"
    INVOICE_PAYMENT_FAILED = "invoice.payment_failed"
    INVOICE_PAYMENT_ACTION_REQUIRED = "invoice.payment_action_required"


class SubscriptionStatus(str, Enum):
    ACTIVE = "active"
    INCOMPLETE = "incomplete"
    INCOMPLETE_EXPIRED = "incomplete_expired"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    UNPAID = "unpaid"
    PAUSED = "paused"
    CANCELED = "canceled"


class EntitlementReason(str, Enum):
    PAID_ACCESS = "paid_access"
    MISSING_EVIDENCE = "missing_evidence"
    INVALID_ASSOCIATION = "invalid_association"
    FUTURE_EVIDENCE = "future_evidence"
    STALE_EVIDENCE = "stale_evidence"
    UNCERTAIN_EVIDENCE = "uncertain_evidence"
    OUTDATED_EVIDENCE = "outdated_evidence"
    CONFLICTING_EVIDENCE = "conflicting_evidence"
    OPERATOR_SUSPENDED = "operator_suspended"
    TERMINAL_CANCELLATION = "terminal_cancellation"
    INACTIVE_SUBSCRIPTION = "inactive_subscription"
    NO_VERIFIED_PAYMENT = "no_verified_payment"
    OUTSIDE_PAID_INTERVAL = "outside_paid_interval"
    SCHEDULED_CANCELLATION = "scheduled_cancellation"


class EventDisposition(str, Enum):
    APPLIED = "applied"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"


def _timestamp(value: object) -> bool:
    return type(value) is int and value >= 0


@dataclass(frozen=True)
class SubscriptionAssociation:
    """Trusted account/tenant mapping and approved price, not customer claims."""

    account_id: str
    customer_id: str
    tenant_id: str
    subscription_id: str
    price_id: str

    def __post_init__(self) -> None:
        if (
            not _valid_customer_tenant(self.tenant_id)
            or not all(_valid_identifier(value) for value in (
                self.account_id, self.customer_id, self.subscription_id, self.price_id,
            ))
        ):
            raise ValueError("Invalid subscription association.")


@dataclass(frozen=True)
class PaidInvoice:
    """Normalized invoice evidence; verification must happen outside this module."""

    invoice_id: str
    association: SubscriptionAssociation
    period_start: int
    period_end: int
    verified: bool

    def __post_init__(self) -> None:
        if (
            not _valid_identifier(self.invoice_id)
            or type(self.association) is not SubscriptionAssociation
            or not _timestamp(self.period_start)
            or not _timestamp(self.period_end)
            or self.period_end <= self.period_start
            or type(self.verified) is not bool
        ):
            raise ValueError("Invalid paid invoice.")


@dataclass(frozen=True)
class SubscriptionEvidence:
    """Reconciled snapshot with a trusted fencing revision, NOT event.created."""

    event_id: str
    event_type: StripeEventType
    association: SubscriptionAssociation
    revision: int
    observed_at: int
    status: SubscriptionStatus
    certain: bool
    invoice: PaidInvoice | None = None
    cancel_at: int | None = None

    def __post_init__(self) -> None:
        invoice_valid = (
            type(self.invoice) is PaidInvoice
            if self.event_type is StripeEventType.INVOICE_PAID
            else self.invoice is None
        )
        if (
            not _valid_identifier(self.event_id)
            or type(self.event_type) is not StripeEventType
            or type(self.association) is not SubscriptionAssociation
            or not _timestamp(self.revision)
            or not _timestamp(self.observed_at)
            or type(self.status) is not SubscriptionStatus
            or type(self.certain) is not bool
            or (self.cancel_at is not None and not _timestamp(self.cancel_at))
            or not invoice_valid
            or (
                self.event_type is StripeEventType.SUBSCRIPTION_DELETED
                and self.status is not SubscriptionStatus.CANCELED
            )
        ):
            raise ValueError("Invalid subscription evidence.")


@dataclass(frozen=True)
class EntitlementState:
    """Caller-retained offline state; no durable or concurrent processing guarantee."""

    association: SubscriptionAssociation
    processed_events: tuple[SubscriptionEvidence, ...] = ()
    paid_invoices: tuple[PaidInvoice, ...] = ()
    terminal_canceled: bool = False
    operator_suspended: bool = False
    uncertain: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.association) is not SubscriptionAssociation
            or type(self.processed_events) is not tuple
            or any(
                type(event) is not SubscriptionEvidence
                or event.association != self.association
                for event in self.processed_events
            )
            or type(self.paid_invoices) is not tuple
            or any(
                type(invoice) is not PaidInvoice
                or invoice.association != self.association or not invoice.verified
                for invoice in self.paid_invoices
            )
            or any(type(flag) is not bool for flag in (
                self.terminal_canceled, self.operator_suspended, self.uncertain,
            ))
        ):
            raise ValueError("Invalid entitlement state.")

    @property
    def latest_evidence(self) -> SubscriptionEvidence | None:
        return max(self.processed_events, key=lambda event: event.revision, default=None)


@dataclass(frozen=True)
class EntitlementDecision:
    reason: EntitlementReason
    access_until: int | None = None

    @property
    def allowed(self) -> bool:
        return self.reason is EntitlementReason.PAID_ACCESS

    def __bool__(self) -> bool:
        return self.allowed


@dataclass(frozen=True)
class EntitlementTransition:
    state: EntitlementState
    disposition: EventDisposition
    decision: EntitlementDecision


def _validate_time(now: int, max_evidence_age: int) -> None:
    if not _timestamp(now) or not _timestamp(max_evidence_age) or max_evidence_age == 0:
        raise ValueError("Invalid entitlement time.")


def _validate_state(state: EntitlementState) -> None:
    if type(state) is not EntitlementState:
        raise ValueError("Invalid entitlement state.")


def evaluate_entitlement(
    state: EntitlementState, *, now: int, max_evidence_age: int,
) -> EntitlementDecision:
    """Assess paid eligibility only; not credential authorization or execution authority."""
    _validate_state(state)
    _validate_time(now, max_evidence_age)
    reasons = EntitlementReason
    if state.operator_suspended:
        return EntitlementDecision(reasons.OPERATOR_SUSPENDED)
    if state.terminal_canceled:
        return EntitlementDecision(reasons.TERMINAL_CANCELLATION)
    latest = state.latest_evidence
    if latest is None:
        return EntitlementDecision(reasons.MISSING_EVIDENCE)
    if now < latest.observed_at:
        return EntitlementDecision(reasons.FUTURE_EVIDENCE)
    freshness_end = latest.observed_at + max_evidence_age
    if now >= freshness_end:
        return EntitlementDecision(reasons.STALE_EVIDENCE)
    if (
        state.uncertain or not latest.certain
        or (latest.invoice is not None and not latest.invoice.verified)
    ):
        return EntitlementDecision(reasons.UNCERTAIN_EVIDENCE)
    if latest.status is not SubscriptionStatus.ACTIVE:
        return EntitlementDecision(reasons.INACTIVE_SUBSCRIPTION)
    if latest.cancel_at is not None and now >= latest.cancel_at:
        return EntitlementDecision(reasons.SCHEDULED_CANCELLATION)
    if not state.paid_invoices:
        return EntitlementDecision(reasons.NO_VERIFIED_PAYMENT)

    paid_until = now
    for invoice in sorted(state.paid_invoices, key=lambda item: item.period_start):
        if invoice.period_start <= paid_until:
            paid_until = max(paid_until, invoice.period_end)
    if paid_until == now:
        return EntitlementDecision(reasons.OUTSIDE_PAID_INTERVAL)
    access_until = min(paid_until, freshness_end)
    if latest.cancel_at is not None:
        access_until = min(access_until, latest.cancel_at)
    return EntitlementDecision(reasons.PAID_ACCESS, access_until)


def suspend_entitlement(state: EntitlementState) -> EntitlementState:
    """Latch independently trusted operator suspension; payment cannot undo it."""
    _validate_state(state)
    return replace(state, operator_suspended=True)


def apply_entitlement_evidence(
    state: EntitlementState,
    evidence: SubscriptionEvidence,
    *,
    now: int,
    max_evidence_age: int,
) -> EntitlementTransition:
    """Return a new state and explicit result without IO, time lookup or mutation."""
    _validate_state(state)
    _validate_time(now, max_evidence_age)
    if type(evidence) is not SubscriptionEvidence:
        raise ValueError("Invalid subscription evidence.")
    reasons = EntitlementReason

    def reject(reason: EntitlementReason, *, uncertain: bool = False) -> EntitlementTransition:
        rejected_state = replace(state, uncertain=True) if uncertain else state
        return EntitlementTransition(
            rejected_state, EventDisposition.REJECTED, EntitlementDecision(reason),
        )

    if state.operator_suspended or state.terminal_canceled:
        return EntitlementTransition(
            state, EventDisposition.REJECTED,
            evaluate_entitlement(state, now=now, max_evidence_age=max_evidence_age),
        )
    if (
        evidence.association != state.association
        or (evidence.invoice is not None and evidence.invoice.association != state.association)
    ):
        return reject(reasons.INVALID_ASSOCIATION)
    for processed in state.processed_events:
        if processed.event_id == evidence.event_id:
            if processed != evidence:
                return reject(reasons.CONFLICTING_EVIDENCE, uncertain=True)
            return EntitlementTransition(
                state, EventDisposition.DUPLICATE,
                evaluate_entitlement(state, now=now, max_evidence_age=max_evidence_age),
            )
    if evidence.observed_at > now:
        return reject(reasons.FUTURE_EVIDENCE)

    # A certain cancellation is a deny-only tombstone, even if delivered late.
    terminal = evidence.certain and evidence.status is SubscriptionStatus.CANCELED
    latest = state.latest_evidence
    if not terminal and latest is not None:
        if evidence.revision == latest.revision:
            return reject(reasons.CONFLICTING_EVIDENCE, uncertain=True)
        if evidence.revision < latest.revision or evidence.observed_at < latest.observed_at:
            return reject(reasons.OUTDATED_EVIDENCE)

    invoices = state.paid_invoices
    certain = (
        evidence.certain
        and now < evidence.observed_at + max_evidence_age
        and (evidence.invoice is None or evidence.invoice.verified)
    )
    if not terminal and certain and evidence.invoice is not None:
        previous = next(
            (item for item in invoices if item.invoice_id == evidence.invoice.invoice_id), None,
        )
        if previous is not None and previous != evidence.invoice:
            return reject(reasons.CONFLICTING_EVIDENCE, uncertain=True)
        if previous is None:
            invoices += (evidence.invoice,)
    updated = replace(
        state,
        processed_events=state.processed_events + (evidence,),
        paid_invoices=invoices,
        terminal_canceled=terminal,
        uncertain=not certain,
    )
    return EntitlementTransition(
        updated, EventDisposition.APPLIED,
        evaluate_entitlement(updated, now=now, max_evidence_age=max_evidence_age),
    )
