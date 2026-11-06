from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Protocol

from gvai.commercial_identity import _valid_customer_tenant, _valid_identifier
from gvai.sandbox_checkout import (
    CheckoutAssociation, CheckoutIntentDenied, SandboxCheckoutConfig, SandboxCheckoutIntent,
    _ATTEMPT, _digest,
)


MAX_GENERATION = 2**63 - 1
_CUSTOMER = re.compile(r"cus_[A-Za-z0-9]{1,124}\Z")
_SESSION = re.compile(r"cs_test_[A-Za-z0-9]{1,120}\Z")
_SUBSCRIPTION = re.compile(r"sub_[A-Za-z0-9]{1,124}\Z")


class AttemptDenied(ValueError):
    """Fixed denial reason, without caller inputs or adapter diagnostics."""


class AttemptStorageUnavailable(RuntimeError):
    """No successful operation is established; do not dispatch."""


class AttemptCommitUnknown(AttemptStorageUnavailable):
    """Reconcile the same durable identity; never allocate a replacement."""


class AttemptState(str, Enum):
    PREPARED = "prepared"
    DISPATCHING = "dispatching"
    SESSION_ATTACHED = "session_attached"
    UNKNOWN = "unknown"
    QUARANTINED = "quarantined"
    EXPIRED_UNSENT = "expired_unsent"
    CLOSED_VERIFIED = "closed_verified"


class SessionStatus(str, Enum):
    OPEN = "open"
    EXPIRED = "expired"
    COMPLETE = "complete"


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise AttemptDenied(reason)


def _time(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_GENERATION


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _validate_intent(intent: SandboxCheckoutIntent) -> None:
    _require(type(intent) is SandboxCheckoutIntent, "invalid_intent")
    association = intent.association
    _require(
        type(association) is CheckoutAssociation
        and all(_valid_identifier(value) for value in (
            association.issuer, association.principal_id,
        ))
        and _valid_customer_tenant(association.tenant_id)
        and type(association.attempt_id) is str
        and _ATTEMPT.fullmatch(association.attempt_id) is not None
        and association.attempt_id != "0" * 32,
        "invalid_intent",
    )
    # Syntax validation only; this does not independently approve a Stripe Price.
    try:
        SandboxCheckoutConfig(
            intent.stripe_account_id, intent.environment, intent.price_id, True,
            intent.success_url, intent.cancel_url,
        )
    except CheckoutIntentDenied:
        raise AttemptDenied("invalid_intent") from None
    _require(
        all(type(value) is int for value in (
            intent.version, intent.unit_amount, intent.recurring_interval_count,
            intent.quantity,
        ))
        and (intent.version, intent.unit_amount, intent.recurring_interval_count,
             intent.quantity) == (1, 9900, 1, 1)
        and all(type(value) is str for value in (
            intent.product, intent.mode, intent.currency, intent.recurring_interval,
            intent.idempotency_key, intent.request_fingerprint,
        ))
        and (intent.product, intent.mode, intent.currency, intent.recurring_interval)
        == ("GVAI Advisory API", "subscription", "usd", "month"),
        "invalid_intent",
    )
    expected_key = "gvai-checkout-v1-" + _digest({
        "domain": "gvai-sandbox-checkout-attempt-v1",
        "account": intent.stripe_account_id, "environment": intent.environment,
        "attempt": association.attempt_id,
    })
    expected_digest = _digest({
        "domain": "gvai-sandbox-checkout-intent-v1",
        "intent": asdict(replace(intent, request_fingerprint="")),
    })
    _require(
        intent.idempotency_key == expected_key
        and intent.request_fingerprint == expected_digest, "intent_digest_conflict",
    )


def _parameters(intent: SandboxCheckoutIntent, customer_id: str) -> bytes:
    return _canonical({
        "mode": intent.mode, "customer": customer_id,
        "line_items": [{"price": intent.price_id, "quantity": intent.quantity}],
        "success_url": intent.success_url, "cancel_url": intent.cancel_url,
        "client_reference_id": intent.association.attempt_id,
    })


@dataclass(frozen=True)
class FrozenCheckoutRequest:
    """Exact adapter input contract, not wire bytes or verified Stripe provenance."""

    intent: SandboxCheckoutIntent
    membership_ref: int
    customer_id: str
    adapter_version: str
    api_version: str
    parameters: bytes

    def __post_init__(self) -> None:
        _validate_intent(self.intent)
        _require(
            type(self.membership_ref) is int and 0 < self.membership_ref <= MAX_GENERATION
            and type(self.customer_id) is str
            and _CUSTOMER.fullmatch(self.customer_id) is not None
            and _valid_identifier(self.adapter_version)
            and _valid_identifier(self.api_version)
            and type(self.parameters) is bytes
            and self.parameters == _parameters(self.intent, self.customer_id),
            "invalid_frozen_request",
        )

    @property
    def fingerprint(self) -> str:
        return _digest({
            "domain": "gvai-frozen-checkout-request-v1",
            "intent": asdict(self.intent), "membership_ref": self.membership_ref,
            "customer_id": self.customer_id, "adapter_version": self.adapter_version,
            "api_version": self.api_version, "parameters": self.parameters.decode("ascii"),
        })

    @property
    def key(self) -> tuple[str, str, str]:
        return (
            self.intent.stripe_account_id, self.intent.environment,
            self.intent.association.attempt_id,
        )


def freeze_checkout_request(
    intent: SandboxCheckoutIntent, *, membership_ref: int, customer_id: str,
    adapter_version: str, api_version: str,
) -> FrozenCheckoutRequest:
    _validate_intent(intent)
    _require(
        type(customer_id) is str and _CUSTOMER.fullmatch(customer_id) is not None,
        "invalid_frozen_request",
    )
    return FrozenCheckoutRequest(
        intent, membership_ref, customer_id, adapter_version, api_version,
        _parameters(intent, customer_id),
    )


@dataclass(frozen=True)
class CheckoutApproval:
    """Trusted current authorization output; constructing it is NOT verification."""

    request: FrozenCheckoutRequest
    expires_at: int
    tenant_active: bool
    membership_active: bool
    checkout_approved: bool
    price_approved: bool
    customer_association_verified: bool
    pilot_present: bool
    subscription_admitted: bool

    def require_current(self, request: FrozenCheckoutRequest, now: int) -> None:
        _require(
            type(self.request) is FrozenCheckoutRequest and self.request == request
            and _time(self.expires_at) and now < self.expires_at
            and all(value is True for value in (
                self.tenant_active, self.membership_active, self.checkout_approved,
                self.price_approved, self.customer_association_verified,
            ))
            and self.pilot_present is False and self.subscription_admitted is False,
            "authorization_denied",
        )


@dataclass(frozen=True)
class VerifiedCheckoutSession:
    """Trusted reconciliation output, never a webhook/client request schema."""

    request: FrozenCheckoutRequest
    session_id: str
    observed_at: int
    expires_at: int
    status: SessionStatus
    subscription_id: str | None = None
    handoff_record_id: str | None = None

    def __post_init__(self) -> None:
        _require(
            type(self.request) is FrozenCheckoutRequest
            and type(self.session_id) is str and _SESSION.fullmatch(self.session_id) is not None
            and _time(self.observed_at) and _time(self.expires_at)
            and type(self.status) is SessionStatus
            and (self.status is not SessionStatus.OPEN or self.observed_at < self.expires_at)
            and (self.status is not SessionStatus.EXPIRED or self.observed_at >= self.expires_at)
            and (
                (self.status is SessionStatus.COMPLETE
                 and type(self.subscription_id) is str
                 and _SUBSCRIPTION.fullmatch(self.subscription_id) is not None)
                or (self.status is not SessionStatus.COMPLETE and self.subscription_id is None)
            )
            and (
                self.handoff_record_id is None
                or (self.status is SessionStatus.COMPLETE and _valid_identifier(self.handoff_record_id))
            ),
            "invalid_session_evidence",
        )


@dataclass(frozen=True)
class CheckoutAttempt:
    request: FrozenCheckoutRequest
    state: AttemptState
    generation: int
    created_at: int
    updated_at: int
    prepare_expires_at: int
    lease_id: str | None = None
    lease_expires_at: int | None = None
    session: VerifiedCheckoutSession | None = None

    def __post_init__(self) -> None:
        _require(
            type(self.request) is FrozenCheckoutRequest
            and type(self.state) is AttemptState
            and type(self.generation) is int and 0 <= self.generation <= MAX_GENERATION
            and all(_time(value) for value in (
                self.created_at, self.updated_at, self.prepare_expires_at,
            ))
            and self.created_at <= self.updated_at
            and self.prepare_expires_at > self.created_at,
            "invalid_attempt",
        )
        _require(
            (self.lease_id is None and self.lease_expires_at is None)
            or (_valid_identifier(self.lease_id) and _time(self.lease_expires_at)
                and self.lease_expires_at > self.updated_at
                and self.state in (
                    AttemptState.DISPATCHING, AttemptState.UNKNOWN,
                    AttemptState.SESSION_ATTACHED,
                )),
            "invalid_lease",
        )
        _require(
            self.state is not AttemptState.DISPATCHING or self.lease_id is not None,
            "invalid_lease",
        )
        _require(
            (self.session is None and self.state not in (
                AttemptState.SESSION_ATTACHED, AttemptState.CLOSED_VERIFIED,
            ))
            or (type(self.session) is VerifiedCheckoutSession
                and self.session.request == self.request
                and self.session.observed_at <= self.updated_at
                and self.state in (
                    AttemptState.SESSION_ATTACHED, AttemptState.CLOSED_VERIFIED,
                    AttemptState.UNKNOWN, AttemptState.QUARANTINED,
                )),
            "invalid_session_association",
        )
        _require(
            self.state is not AttemptState.CLOSED_VERIFIED
            or (self.session is not None and (
                self.session.status is SessionStatus.EXPIRED
                or self.session.handoff_record_id is not None
            )),
            "unverified_closure",
        )
        _require(
            self.state is not AttemptState.EXPIRED_UNSENT
            or self.updated_at >= self.prepare_expires_at, "not_proven_unsent",
        )

    @property
    def holds_tenant_slot(self) -> bool:
        return self.state not in (AttemptState.EXPIRED_UNSENT, AttemptState.CLOSED_VERIFIED)


def prepare_attempt(
    request: FrozenCheckoutRequest, approval: CheckoutApproval, *,
    now: int, expires_at: int,
) -> CheckoutAttempt:
    _require(_time(now) and type(approval) is CheckoutApproval, "invalid_prepare")
    approval.require_current(request, now)
    return CheckoutAttempt(request, AttemptState.PREPARED, 0, now, now, expires_at)


def resolve_prepare(
    candidate: CheckoutAttempt, *, existing: CheckoutAttempt | None,
    tenant_slot: CheckoutAttempt | None,
) -> CheckoutAttempt:
    """Pure snapshot check; future storage must perform it under tenant-wide locks."""
    _require(
        type(candidate) is CheckoutAttempt and candidate.state is AttemptState.PREPARED
        and candidate.generation == 0, "invalid_prepare",
    )
    if existing is not None:
        _require(
            type(existing) is CheckoutAttempt
            and existing.request.key == candidate.request.key
            and existing.request == candidate.request, "attempt_conflict",
        )
        return existing
    if tenant_slot is not None:
        _require(type(tenant_slot) is CheckoutAttempt, "invalid_tenant_slot")
        _require(
            tenant_slot.request.intent.association.tenant_id
            == candidate.request.intent.association.tenant_id, "invalid_tenant_slot",
        )
        _require(not tenant_slot.holds_tenant_slot, "tenant_purchase_unresolved")
    return candidate


def _check(record: CheckoutAttempt, expected_generation: int, now: int) -> None:
    _require(type(record) is CheckoutAttempt and _time(now), "invalid_transition")
    _require(
        type(expected_generation) is int and expected_generation == record.generation,
        "stale_generation",
    )
    _require(now >= record.updated_at, "clock_rollback")


def _advance(record: CheckoutAttempt, now: int, **changes: object) -> CheckoutAttempt:
    _require(record.generation < MAX_GENERATION, "generation_exhausted")
    return replace(record, generation=record.generation + 1, updated_at=now, **changes)


def claim_attempt(
    record: CheckoutAttempt, approval: CheckoutApproval, *, expected_generation: int,
    lease_id: str, now: int, lease_seconds: int,
) -> CheckoutAttempt:
    _check(record, expected_generation, now)
    _require(record.state is AttemptState.PREPARED, "creation_not_claimable")
    _require(now < record.prepare_expires_at, "prepare_expired")
    _require(type(approval) is CheckoutApproval, "authorization_denied")
    approval.require_current(record.request, now)
    _lease_bounds(lease_id, lease_seconds, now)
    return _advance(
        record, now, state=AttemptState.DISPATCHING, lease_id=lease_id,
        lease_expires_at=now + lease_seconds,
    )


def _lease_bounds(lease_id: str, lease_seconds: int, now: int) -> None:
    _require(
        _valid_identifier(lease_id) and type(lease_seconds) is int
        and 1 <= lease_seconds <= 300 and now + lease_seconds <= MAX_GENERATION,
        "invalid_lease",
    )


def claim_recovery(
    record: CheckoutAttempt, *, expected_generation: int, lease_id: str,
    now: int, lease_seconds: int,
) -> CheckoutAttempt:
    _check(record, expected_generation, now)
    _require(record.state in (
        AttemptState.DISPATCHING, AttemptState.UNKNOWN, AttemptState.SESSION_ATTACHED,
    ), "recovery_not_claimable")
    _require(
        record.lease_expires_at is None or now >= record.lease_expires_at,
        "lease_busy",
    )
    _lease_bounds(lease_id, lease_seconds, now)
    return _advance(
        record, now,
        state=(AttemptState.SESSION_ATTACHED if record.session is not None else AttemptState.UNKNOWN),
        lease_id=lease_id, lease_expires_at=now + lease_seconds,
    )


def mark_unknown(
    record: CheckoutAttempt, *, expected_generation: int, now: int,
) -> CheckoutAttempt:
    """May run after lease expiry; full-record CAS is still mandatory in storage."""
    _check(record, expected_generation, now)
    _require(record.state in (
        AttemptState.DISPATCHING, AttemptState.UNKNOWN, AttemptState.SESSION_ATTACHED,
    ), "invalid_transition")
    return _advance(
        record, now, state=AttemptState.UNKNOWN, lease_id=None, lease_expires_at=None,
    )


def quarantine_attempt(
    record: CheckoutAttempt, *, expected_generation: int, now: int,
) -> CheckoutAttempt:
    _check(record, expected_generation, now)
    _require(record.holds_tenant_slot and record.state is not AttemptState.QUARANTINED,
             "invalid_transition")
    return _advance(
        record, now, state=AttemptState.QUARANTINED, lease_id=None, lease_expires_at=None,
    )


def expire_unsent(
    record: CheckoutAttempt, *, expected_generation: int, now: int,
) -> CheckoutAttempt:
    _check(record, expected_generation, now)
    _require(
        record.state is AttemptState.PREPARED and now >= record.prepare_expires_at,
        "not_proven_unsent",
    )
    return _advance(record, now, state=AttemptState.EXPIRED_UNSENT)


def confirm_session(
    record: CheckoutAttempt, evidence: VerifiedCheckoutSession, *,
    expected_generation: int, lease_id: str, now: int,
) -> CheckoutAttempt:
    _check(record, expected_generation, now)
    if (
        record.state is AttemptState.SESSION_ATTACHED and record.lease_id is None
        and type(evidence) is VerifiedCheckoutSession and record.session == evidence
    ):
        return record
    _require(
        record.state in (
            AttemptState.DISPATCHING, AttemptState.UNKNOWN, AttemptState.SESSION_ATTACHED,
        ) and _valid_identifier(lease_id) and lease_id == record.lease_id
        and record.lease_expires_at is not None and now < record.lease_expires_at,
        "stale_lease",
    )
    _require(
        type(evidence) is VerifiedCheckoutSession and evidence.request == record.request
        and record.updated_at <= evidence.observed_at <= now, "session_association_denied",
    )
    if record.session is not None:
        _require(
            evidence.session_id == record.session.session_id
            and evidence.observed_at >= record.session.observed_at
            and evidence.expires_at == record.session.expires_at
            and (record.session.status is SessionStatus.OPEN
                 or evidence.status is record.session.status)
            and (record.session.subscription_id is None
                 or evidence.subscription_id == record.session.subscription_id)
            and (record.session.handoff_record_id is None
                 or evidence.handoff_record_id == record.session.handoff_record_id),
            "session_conflict",
        )
    return _advance(
        record, now, state=AttemptState.SESSION_ATTACHED, session=evidence,
        lease_id=None, lease_expires_at=None,
    )


def close_verified(
    record: CheckoutAttempt, *, expected_generation: int, now: int,
) -> CheckoutAttempt:
    _check(record, expected_generation, now)
    _require(
        record.state is AttemptState.SESSION_ATTACHED and record.lease_id is None,
        "invalid_transition",
    )
    _require(
        record.session is not None and (
            record.session.status is SessionStatus.EXPIRED
            or record.session.handoff_record_id is not None
        ), "unverified_closure",
    )
    return _advance(
        record, now, state=AttemptState.CLOSED_VERIFIED,
        lease_id=None, lease_expires_at=None,
    )


def validate_recovery(
    expected: CheckoutAttempt, candidate: CheckoutAttempt,
) -> CheckoutAttempt:
    """Validate a proposed recovery write; this does not perform the durable CAS."""
    _require(
        type(expected) is CheckoutAttempt and type(candidate) is CheckoutAttempt
        and candidate.request == expected.request
        and candidate.created_at == expected.created_at
        and candidate.prepare_expires_at == expected.prepare_expires_at,
        "immutable_attempt_conflict",
    )
    arguments = {"expected_generation": expected.generation, "now": candidate.updated_at}
    if candidate.state is AttemptState.UNKNOWN and candidate.lease_id is None:
        proposed = mark_unknown(expected, **arguments)
    elif candidate.state is AttemptState.QUARANTINED:
        proposed = quarantine_attempt(expected, **arguments)
    elif candidate.state is AttemptState.EXPIRED_UNSENT:
        proposed = expire_unsent(expected, **arguments)
    elif candidate.state is AttemptState.CLOSED_VERIFIED:
        proposed = close_verified(expected, **arguments)
    elif candidate.lease_id is not None and candidate.lease_expires_at is not None:
        proposed = claim_recovery(
            expected, **arguments, lease_id=candidate.lease_id,
            lease_seconds=candidate.lease_expires_at - candidate.updated_at,
        )
    else:
        raise AttemptDenied("invalid_recovery")
    _require(candidate == proposed, "invalid_recovery")
    return candidate


class CheckoutAttemptStore(Protocol):
    """Transactional contract only. No durable or in-memory implementation supplied.

    Every operation must CAS the complete expected record, not generation alone.
    Prepare/claim must re-read authorization and tenant-wide purchase admission.
    Return only after known commit; ambiguous commits raise AttemptCommitUnknown.
    Recovery never authorizes another create call. Exceptions never imply success.
    """

    def prepare(self, candidate: CheckoutAttempt, approval: CheckoutApproval) -> CheckoutAttempt:
        """Atomically bind key/request, compare replays, and acquire the tenant slot."""
        ...

    def claim(
        self, expected: CheckoutAttempt, approval: CheckoutApproval,
        *, lease_id: str, lease_seconds: int,
    ) -> CheckoutAttempt:
        """Commit dispatch intent before a future adapter can consider an API call."""
        ...

    def confirm(
        self, expected: CheckoutAttempt, evidence: VerifiedCheckoutSession,
    ) -> CheckoutAttempt:
        """Fence attachment, enforce scoped session uniqueness, compare exact replays."""
        ...

    def recover(self, expected: CheckoutAttempt, candidate: CheckoutAttempt) -> CheckoutAttempt:
        """Use validate_recovery under the same CAS transaction; never arbitrary replace."""
        ...
