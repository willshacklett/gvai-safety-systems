from __future__ import annotations

import hashlib
import math
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Mapping

from gvai.commercial_identity import (
    CommercialAuthorizer,
    CommercialCapability,
    _valid_customer_tenant,
    _valid_identifier,
)


MAX_EVALUATION_UNITS = (1 << 63) - 1


class UsageReason(str, Enum):
    RESERVED = "reserved"
    REPLAY = "replay"
    COMPLETED = "completed"
    FAILED = "failed"
    SUMMARY = "summary"
    UNAUTHORIZED = "unauthorized"
    INVALID_INPUT = "invalid_input"
    POLICY_MISSING = "policy_missing"
    QUOTA_EXHAUSTED = "quota_exhausted"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"
    CLOCK_ROLLBACK = "clock_rollback"
    ACCOUNTING_ERROR = "accounting_error"


class ReservationState(str, Enum):
    RESERVED = "reserved"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class UsageReservation:
    period: str
    resource_digest: str
    state: ReservationState = ReservationState.RESERVED


@dataclass(frozen=True)
class UsageSummary:
    period: str
    allowance: int
    consumed: int
    remaining: int
    reserved: int
    completed: int
    failed: int


@dataclass(frozen=True)
class UsageResult:
    reason: UsageReason
    reservation: UsageReservation | None = None
    summary: UsageSummary | None = None

    @property
    def outcome(self) -> str:
        if self.reason is UsageReason.ACCOUNTING_ERROR:
            return "error"
        if self.reason in {
            UsageReason.RESERVED, UsageReason.REPLAY, UsageReason.COMPLETED,
            UsageReason.FAILED, UsageReason.SUMMARY,
        }:
            return "success"
        return "denied"

    @property
    def may_evaluate(self) -> bool:
        return self.reason is UsageReason.RESERVED

    def __bool__(self) -> bool:
        return self.may_evaluate


@dataclass(frozen=True)
class _TenantLedger:
    last_seen: float
    counts: dict[str, int]
    reservations: dict[str, UsageReservation]


def _digest(value: str) -> str:
    return hashlib.sha256(b"gvai-usage-v1\x00" + value.encode("ascii")).hexdigest()


class InMemoryUsageStore:
    """NONPRODUCTION: one process, one shared object, no durable accounting.

    Construct only in trusted server code. Policies are copied at construction;
    there is no customer policy mutation, refund, reset, or pruning operation.
    """

    def __init__(
        self,
        allowances: Mapping[str, int],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        policies = dict(allowances)
        if any(
            not _valid_customer_tenant(tenant)
            or type(allowance) is not int
            or not 0 <= allowance <= MAX_EVALUATION_UNITS
            for tenant, allowance in policies.items()
        ):
            raise ValueError("Invalid usage policy.")
        self._allowances = policies
        self._clock = clock
        self._lock = threading.Lock()
        self._ledgers: dict[str, _TenantLedger] = {}

    def _apply(
        self,
        tenant_id: str,
        resource_id: str,
        request_id: str | None,
        operation: str,
    ) -> UsageResult:
        with self._lock:
            if tenant_id not in self._allowances:
                return UsageResult(UsageReason.POLICY_MISSING)
            now = self._clock()
            if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
                raise ValueError
            instant = datetime.fromtimestamp(math.floor(now), timezone.utc)
            if instant.year >= 9999:
                raise ValueError
            period = instant.strftime("%Y-%m")
            ledger = self._ledgers.get(tenant_id, _TenantLedger(now, {}, {}))
            if now < ledger.last_seen:
                return UsageResult(UsageReason.CLOCK_ROLLBACK)
            allowance = self._allowances[tenant_id]
            consumed = ledger.counts.get(period, 0)
            if type(consumed) is not int or not 0 <= consumed <= allowance:
                raise ValueError
            counts = ledger.counts.copy()
            reservations = ledger.reservations.copy()
            if operation == "summary":
                states = [record.state for record in reservations.values() if record.period == period]
                if len(states) != consumed or any(type(state) is not ReservationState for state in states):
                    raise ValueError
                summary = UsageSummary(
                    period, allowance, consumed, allowance - consumed,
                    states.count(ReservationState.RESERVED),
                    states.count(ReservationState.COMPLETED),
                    states.count(ReservationState.FAILED),
                )
                result = UsageResult(UsageReason.SUMMARY, summary=summary)
            else:
                key = _digest(request_id)
                resource_digest = _digest(resource_id)
                record = reservations.get(key)
                if record is not None and record.resource_digest != resource_digest:
                    result = UsageResult(UsageReason.CONFLICT)
                elif operation == "reserve":
                    if record is not None:
                        result = UsageResult(UsageReason.REPLAY, reservation=record)
                    elif consumed >= allowance:
                        result = UsageResult(UsageReason.QUOTA_EXHAUSTED)
                    else:
                        record = UsageReservation(period, resource_digest)
                        reservations[key] = record
                        counts[period] = consumed + 1
                        result = UsageResult(UsageReason.RESERVED, reservation=record)
                elif record is None:
                    result = UsageResult(UsageReason.NOT_FOUND)
                else:
                    target = ReservationState(operation)
                    if record.state is target:
                        result = UsageResult(UsageReason.REPLAY, reservation=record)
                    elif record.state is not ReservationState.RESERVED:
                        result = UsageResult(UsageReason.CONFLICT)
                    else:
                        record = UsageReservation(record.period, record.resource_digest, target)
                        reservations[key] = record
                        reason = UsageReason.COMPLETED if target is ReservationState.COMPLETED else UsageReason.FAILED
                        result = UsageResult(reason, reservation=record)
            self._ledgers[tenant_id] = _TenantLedger(now, counts, reservations)
            return result


class CommercialUsage:
    """Offline accounting only. Never evaluates, executes, or controls work.

    Dependencies and completion calls are trusted server code, not request
    schemas. Every call re-enters CommercialAuthorizer; decisions are not cached.
    """

    def __init__(self, authorizer: CommercialAuthorizer, store: InMemoryUsageStore) -> None:
        self._authorizer = authorizer
        self._store = store

    def reserve(self, credential: object, resource_id: str, request_id: str) -> UsageResult:
        return self._operate(credential, resource_id, request_id, "reserve")

    def complete(
        self, credential: object, resource_id: str, request_id: str, *, succeeded: bool,
    ) -> UsageResult:
        if type(succeeded) is not bool:
            return UsageResult(UsageReason.INVALID_INPUT)
        operation = "completed" if succeeded else "failed"
        return self._operate(credential, resource_id, request_id, operation)

    def summary(self, credential: object, resource_id: str) -> UsageResult:
        return self._operate(credential, resource_id, None, "summary")

    def _operate(
        self, credential: object, resource_id: str, request_id: str | None, operation: str,
    ) -> UsageResult:
        try:
            if operation != "summary" and not _valid_identifier(request_id):
                return UsageResult(UsageReason.INVALID_INPUT)
            capability = (
                CommercialCapability.READ_USAGE if operation == "summary"
                else CommercialCapability.EVALUATE
            )
            decision = self._authorizer.authorize(credential, capability, resource_id)
            if decision.allowed is not True or not _valid_customer_tenant(decision.tenant_id):
                return UsageResult(UsageReason.UNAUTHORIZED)
            return self._store._apply(decision.tenant_id, resource_id, request_id, operation)
        except Exception:
            return UsageResult(UsageReason.ACCOUNTING_ERROR)
