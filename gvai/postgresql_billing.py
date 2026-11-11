from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import logging
import re
import time
from typing import Any, Callable, Iterator

from gvai.commercial_api_keys import api_key_credential_material
from gvai.commercial_identity import _valid_customer_tenant, _valid_identifier
from gvai.commercial_reservation_authority import AuthorityIdentity, CanonicalReservationRequest
from gvai.commercial_usage import UsageReason, UsageReservation, UsageResult
from gvai.postgresql_advisory import AdvisoryAccountingUnavailable, AdvisoryPilotUsage
from gvai.stripe_billing import (
    ALLOWANCE, BillingUnavailable, PaidState, fail, https_url, identifier,
)


LOG = logging.getLogger(__name__)
PAID_ENTRY_FUNCTIONS = (
    "billing_upgrade_ready_v1()",
    "billing_integrity_ready_v12()",
    "reserve_paid_v1(text,bytea,text,bigint,text,text,text,text)",
    "complete_paid_v1(text,bytea,text,text,boolean)",
    "paid_usage_v1(text,bytea,text)",
)
ConnectionFactory = Callable[[], Any]


@contextmanager
def _transaction(connect: ConnectionFactory) -> Iterator[Any]:
    try:
        with connect() as connection, connection.cursor() as cursor:
            yield cursor
    except BillingUnavailable:
        raise
    except Exception:
        raise fail("database_operation_uncertain") from None


RECONCILER_ENTRY_FUNCTIONS = (
    "billing_upgrade_ready_v1()",
    "billing_integrity_ready_v12()",
    "reconcile_claim_due_v1(integer,integer)",
    "reconcile_signal_v1(text,text,text,bigint,boolean)",
    "reconcile_signal_v1(text,text,text,bigint,boolean,text,text)",
    "reconcile_apply_v1(text,bigint,bigint,bigint,text,text,bigint,bigint,boolean,bigint,boolean)",
    "reconcile_fail_v1(text,bigint,text,text)",
    "reconcile_status_v1()",
)
APPLIED = frozenset({"applied_eligible", "applied_denied", "covered_by_newer"})
TRANSIENT_OUTCOMES = frozenset({
    "stale_snapshot", "ticket_invalid", "observation_missing", "clock_skew", "transient_failure",
})
MAX_EVENT_ATTEMPTS = 3


@dataclass(frozen=True)
class Claim:
    customer: str
    subscription: str | None
    repin: bool
    ticket: int
    phase: str
    lag: float


class ReconcileFunctions:
    """Reconciliation through the audited SECURITY DEFINER functions only.

    Stripe is read only between two short database calls: no transaction, row lock or
    connection is held while a provider request is outstanding.
    """

    connect: ConnectionFactory
    sleep: Callable[[float], None] = staticmethod(time.sleep)

    def _call(self, sql: str, parameters: tuple[Any, ...]) -> list[tuple[Any, ...]]:
        with _transaction(self.connect) as cursor:
            cursor.execute(sql, parameters)
            return list(cursor.fetchall())

    def claim_due(self, limit: int = 5, claim_seconds: int = 30) -> list[Claim]:
        rows = self._call(
            "SELECT o_customer,o_subscription,o_repin,o_ticket,o_phase,o_lag "
            "FROM gvai_authority.reconcile_claim_due_v1(%s,%s)", (limit, claim_seconds),
        )
        return [Claim(row[0], row[1], row[2], row[3], row[4], float(row[5])) for row in rows]

    def status(self) -> dict[str, Any]:
        value = self._call("SELECT gvai_authority.reconcile_status_v1()", ())[0][0]
        if type(value) is not dict:
            raise fail("status_rejected")
        return value

    def _claim_single(self, customer: str) -> Claim | None:
        raise fail("operator_claim_unavailable")

    def _signal(self, customer: str, event: tuple[str, str, int, bool]) -> Claim | None:
        event_id, digest, created, denial = event[:4]
        scope = event[4:]
        if len(scope) not in (0, 2):
            raise fail("event_scope_rejected")
        identifier(event_id, "evt_")
        if (
            type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or type(created) is not int or type(denial) is not bool
        ):
            raise fail("event_digest_rejected")
        rows = self._call(
            "SELECT o_duplicate,o_subscription,o_repin,o_ticket FROM gvai_authority.reconcile_signal_v1("
            + ",".join(["%s"] * (5 + len(scope))) + ")",
            (customer, event_id, digest, created, denial) + scope,
        )
        if not rows:
            raise fail("unmapped_customer")
        duplicate, subscription, repin, ticket = rows[0]
        if duplicate:
            return None
        return Claim(customer, subscription, repin, ticket, "signal", 0.0)

    def complete(self, claim: Claim, load: Callable[[str | None, bool], PaidState]) -> str:
        """Fetch Stripe state for a claimed ticket and apply or fail it; never holds a lock."""
        try:
            state = load(claim.subscription, claim.repin)
            if type(state) is not PaidState:
                raise fail("state_rejected")
            for number in (state.observed_min, state.observed_max, state.start, state.end, state.access_until):
                if number is not None and type(number) is not int:
                    raise fail("state_rejected")
            if state.subscription is not None:
                identifier(state.subscription, "sub_")
            eligible = state.eligible is True
        except BillingUnavailable as error:
            return self._failure(claim, error.transient, error.code)
        except Exception:
            LOG.warning("stripe_billing: unexpected_reconciliation_error")
            return self._failure(claim, False, "unexpected_error")
        return self._call(
            "SELECT gvai_authority.reconcile_apply_v1(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (claim.customer, claim.ticket, state.observed_min, state.observed_max, state.subscription,
             state.invoice if eligible else None, state.start if eligible else None,
             state.end if eligible else None, eligible, state.access_until if eligible else None,
             state.terminal is True),
        )[0][0]

    def _failure(self, claim: Claim, transient: bool, code: str) -> str:
        outcome = self._call(
            "SELECT gvai_authority.reconcile_fail_v1(%s,%s,%s,%s)",
            (claim.customer, claim.ticket, "transient" if transient else "integrity", code),
        )[0][0]
        return "transient_failure" if transient and outcome != "ticket_invalid" else outcome

    def reconcile(
        self, customer: str, load: Callable[[str | None, bool], PaidState],
        *, event: tuple[str, str, int, bool] | None = None,
    ) -> bool:
        identifier(customer, "cus_")
        for attempt in range(1, MAX_EVENT_ATTEMPTS + 1):
            claim = self._claim_single(customer) if event is None else self._signal(customer, event)
            if claim is None:
                return False
            outcome = self.complete(claim, load)
            if outcome in APPLIED:
                return True
            if outcome == "duplicate_event":
                return False
            if outcome == "stale_snapshot" and attempt < MAX_EVENT_ATTEMPTS:
                # Stripe's clock has second resolution; wait until a read is strictly newer.
                self.sleep(1.1)
                continue
            break
        raise fail("reconciliation_" + re.sub(r"[^a-z0-9_]", "_", outcome.lower())[:40],
                   transient=outcome in TRANSIENT_OUTCOMES)


class PostgreSQLReconcilerStore(ReconcileFunctions):
    """Least-privilege reconciler role: function execution only, no table access."""

    def __init__(self, connect: ConnectionFactory) -> None:
        self.connect = connect


class PostgreSQLBillingStore(ReconcileFunctions):
    """Owner-only control plane. No raw event bodies or payment details are stored."""

    def __init__(self, connect: ConnectionFactory) -> None:
        self.connect = connect

    def bind(self, tenant: str, customer: str) -> None:
        if not _valid_customer_tenant(tenant):
            raise fail("tenant_rejected")
        identifier(customer, "cus_")
        with _transaction(self.connect) as cursor:
            cursor.execute(
                "SELECT tenant_ref FROM gvai_authority.tenants "
                "WHERE tenant_id=%s AND status='active' FOR UPDATE", (tenant,),
            )
            row = cursor.fetchone()
            if row is None:
                raise fail("tenant_not_found")
            cursor.execute(
                "INSERT INTO gvai_authority.billing_customers(tenant_ref,customer_id) "
                "VALUES(%s,%s) ON CONFLICT(tenant_ref) DO NOTHING", (row[0], customer),
            )
            cursor.execute(
                "SELECT customer_id FROM gvai_authority.billing_customers WHERE tenant_ref=%s",
                (row[0],),
            )
            if cursor.fetchone() != (customer,):
                raise fail("customer_rebinding_rejected")

    def customer(self, tenant: str) -> str:
        if not _valid_customer_tenant(tenant):
            raise fail("tenant_rejected")
        with _transaction(self.connect) as cursor:
            cursor.execute(
                "SELECT b.customer_id FROM gvai_authority.billing_customers b "
                "JOIN gvai_authority.tenants t ON t.tenant_ref=b.tenant_ref WHERE t.tenant_id=%s",
                (tenant,),
            )
            row = cursor.fetchone()
            if row is None:
                raise fail("billing_mapping_missing")
            return row[0]

    def _claim_single(self, customer: str) -> Claim | None:
        rows = self._call(
            "SELECT o_customer,o_subscription,o_repin,o_ticket,o_phase,o_lag "
            "FROM gvai_authority.reconcile_claim_one_v1(%s,%s)", (customer, 30),
        )
        if not rows:
            raise fail("claim_in_flight", transient=True)
        row = rows[0]
        return Claim(row[0], row[1], row[2], row[3], row[4], float(row[5]))

    def recover_denial(self, tenant: str, denial: str, raw: bytes, signature: str,
                       reason: str, authority: Any) -> str:
        """Owner-only recovery from signed payment evidence plus a freshly verified chain."""
        from gvai.stripe_billing import verified_recovery_event

        customer = self.customer(tenant)
        event = verified_recovery_event(raw, signature, authority.config, int(authority.clock()))
        value = event["data"]["object"]
        if value.get("customer") != customer:
            raise fail("recovery_customer_mismatch")
        claim = self._claim_single(customer)
        state = authority.current(customer, claim.subscription, claim.repin)
        if (not state.eligible or state.terminal or state.invoice != value.get("id")
                or state.subscription != value.get("subscription")):
            raise fail("recovery_payment_mismatch")
        return self._call(
            "SELECT gvai_authority.reconcile_recover_denial_v1("
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (customer, denial, event["id"], hashlib.sha256(raw).hexdigest(), value["status_transitions"]["paid_at"],
             reason, claim.ticket, state.observed_min, state.observed_max, state.subscription,
             state.invoice, state.start, state.end, state.access_until),
        )[0][0]

    def resume(self, tenant: str) -> bool:
        customer = self.customer(tenant)
        return self._call("SELECT gvai_authority.reconcile_resume_v1(%s)", (customer,))[0][0] is True

    def revoke(self, tenant: str) -> None:
        customer = self.customer(tenant)
        with _transaction(self.connect) as cursor:
            cursor.execute(
                "UPDATE gvai_authority.billing_customers SET revoked=true,eligible=false "
                "WHERE customer_id=%s RETURNING tenant_ref", (customer,),
            )
            if cursor.fetchone() is None:
                raise fail("billing_revocation_unconfirmed")

    @staticmethod
    def _lock(cursor: Any, customer: str) -> tuple[Any, ...]:
        cursor.execute(
            "SELECT b.tenant_ref,b.subscription_id,b.revoked FROM gvai_authority.billing_customers b "
            "JOIN gvai_authority.tenants t ON t.tenant_ref=b.tenant_ref "
            "WHERE b.customer_id=%s FOR UPDATE OF t,b", (customer,),
        )
        row = cursor.fetchone()
        if row is None:
            raise fail("unmapped_customer")
        return row

    def checkout(self, tenant: str, create: Callable[[str, int, bool], dict[str, Any]]) -> str:
        customer = self.customer(tenant)
        with _transaction(self.connect) as cursor:
            self._lock(cursor, customer)
            cursor.execute("SELECT revoked FROM gvai_authority.billing_customers WHERE customer_id=%s", (customer,))
            if cursor.fetchone()[0]:
                raise fail("checkout_requires_operator_recovery")
            # Opens a resubscription only for a terminal subscription; otherwise returns the
            # current generation. Persists intent before any external call.
            cursor.execute("SELECT gvai_authority.reconcile_begin_resubscribe_v1(%s)", (customer,))
            generation = cursor.fetchone()[0]
            cursor.execute(
                "UPDATE gvai_authority.billing_customers "
                "SET checkout_started_at=COALESCE(checkout_started_at,clock_timestamp()) "
                "WHERE customer_id=%s", (customer,),
            )
        with _transaction(self.connect) as cursor:
            cursor.execute(
                "SELECT checkout_session_id,checkout_url,"
                "checkout_started_at>clock_timestamp()-interval '23 hours',repin_allowed,checkout_generation "
                "FROM gvai_authority.billing_customers WHERE customer_id=%s", (customer,),
            )
            session_id, url, retryable, repin, current = cursor.fetchone()
        if not retryable or current != generation:
            raise fail("checkout_requires_operator_recovery")
        if session_id is not None:
            return https_url(url, host="checkout.stripe.com")
        # Stripe is called with no transaction or row lock held; the generation-scoped
        # idempotency key makes concurrent duplicate calls return the same session.
        value = create(customer, generation, repin)
        identifier(value.get("id"), "cs_test_")
        if (
            value.get("object") != "checkout.session" or value.get("livemode") is not False
            or value.get("customer") != customer or value.get("mode") != "subscription"
        ):
            raise fail("checkout_binding_rejected")
        url = https_url(value.get("url"), host="checkout.stripe.com")
        with _transaction(self.connect) as cursor:
            self._lock(cursor, customer)
            cursor.execute(
                "UPDATE gvai_authority.billing_customers SET checkout_session_id=%s,checkout_url=%s "
                "WHERE customer_id=%s AND checkout_generation=%s AND NOT revoked "
                "AND (checkout_session_id IS NULL OR checkout_session_id=%s) RETURNING 1",
                (value["id"], url, customer, generation, value["id"]),
            )
            if cursor.fetchone() is None:
                raise fail("checkout_requires_operator_recovery")
        return url


class PostgreSQLPaidUsage:
    """Separate paid ledger; never falls back to or resets a pilot allowance."""

    def __init__(
        self, connection_factory: ConnectionFactory, *, authority: AuthorityIdentity,
        credential_verifier_secret: bytes,
    ) -> None:
        if type(authority) is not AuthorityIdentity or type(credential_verifier_secret) is not bytes or len(credential_verifier_secret) < 32:
            raise ValueError("Pinned authority and verifier are required.")
        self._connect, self._authority, self._secret = connection_factory, authority, credential_verifier_secret

    def _operation(self, sql: str, parameters: tuple[Any, ...]) -> UsageResult:
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(sql, parameters)
                row = cursor.fetchone()
                reason = UsageReason(row[0]) if row is not None else UsageReason.ACCOUNTING_ERROR
                reservation = (
                    UsageReservation("stripe-paid-period", hashlib.sha256(parameters[-2].encode()).hexdigest())
                    if reason is UsageReason.RESERVED else None
                )
            return UsageResult(reason, reservation)
        except Exception:
            LOG.warning("paid_advisory: accounting_unavailable_no_retry")
            return UsageResult(UsageReason.ACCOUNTING_ERROR)

    def reserve_evaluation(self, credential: object, resource_id: str, request_id: str, payload: bytes) -> UsageResult:
        material = api_key_credential_material(credential, self._secret)
        if material is None:
            return UsageResult(UsageReason.UNAUTHORIZED)
        try:
            request = CanonicalReservationRequest.from_bounded_input(request_id, resource_id, payload)
        except ValueError:
            return UsageResult(UsageReason.INVALID_INPUT)
        return self._operation(
            "SELECT gvai_authority.reserve_paid_v1(%s,%s,%s,%s,%s,%s,%s,%s)",
            (*material, self._authority.authority_id, self._authority.epoch,
             self._authority.trust_domain, request.request_id, request.resource_id, request.payload_digest),
        )

    def complete(self, credential: object, resource_id: str, request_id: str, *, succeeded: bool) -> UsageResult:
        material = api_key_credential_material(credential, self._secret)
        if material is None:
            return UsageResult(UsageReason.UNAUTHORIZED)
        if not _valid_identifier(resource_id) or not _valid_identifier(request_id) or type(succeeded) is not bool:
            return UsageResult(UsageReason.INVALID_INPUT)
        return self._operation(
            "SELECT gvai_authority.complete_paid_v1(%s,%s,%s,%s,%s)",
            (*material, resource_id, request_id, succeeded),
        )

    def summary(self, credential: object, resource_id: str) -> AdvisoryPilotUsage | None:
        material = api_key_credential_material(credential, self._secret)
        if material is None or not _valid_identifier(resource_id):
            return None
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT * FROM gvai_authority.paid_usage_v1(%s,%s,%s)", (*material, resource_id))
                row = cursor.fetchone()
            if row is None:
                return None
            if (
                len(row) != 5 or any(type(value) is not int or value < 0 for value in row)
                or row[0] != ALLOWANCE or row[1] > row[0] or sum(row[2:]) != row[1]
            ):
                raise ValueError
            return AdvisoryPilotUsage(*row)
        except Exception:
            LOG.warning("paid_advisory: summary_unavailable")
            raise AdvisoryAccountingUnavailable("Paid usage unavailable.") from None
