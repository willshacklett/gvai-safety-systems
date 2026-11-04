from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import logging
import re
from typing import Any, Callable, Iterator

from gvai.commercial_api_keys import api_key_credential_material
from gvai.commercial_identity import _valid_customer_tenant, _valid_identifier
from gvai.commercial_reservation_authority import AuthorityIdentity, CanonicalReservationRequest
from gvai.commercial_usage import UsageReason, UsageReservation, UsageResult
from gvai.postgresql_advisory import AdvisoryAccountingUnavailable, AdvisoryPilotUsage
from gvai.stripe_billing import (
    ALLOWANCE, FRESH_SECONDS, BillingUnavailable, PaidState, fail, https_url, identifier,
)


LOG = logging.getLogger(__name__)
PAID_ENTRY_FUNCTIONS = (
    "reserve_paid_v1(text,bytea,text,bigint,text,text,text,text)",
    "complete_paid_v1(text,bytea,text,text,boolean)",
    "paid_usage_v1(text,bytea,text)",
)
ConnectionFactory = Callable[[], Any]


def _instant(value: int) -> datetime:
    return datetime.fromtimestamp(value, timezone.utc)


@contextmanager
def _transaction(connect: ConnectionFactory) -> Iterator[Any]:
    try:
        with connect() as connection, connection.cursor() as cursor:
            yield cursor
    except BillingUnavailable:
        raise
    except Exception:
        raise fail("database_operation_uncertain") from None


class PostgreSQLBillingStore:
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

    def reconcile(
        self, customer: str, load: Callable[[str | None], PaidState],
        *, event: tuple[str, str] | None = None,
    ) -> bool:
        identifier(customer, "cus_")
        unavailable = False
        with _transaction(self.connect) as cursor:
            tenant, pinned, revoked = self._lock(cursor, customer)
            if event is not None:
                identifier(event[0], "evt_")
                if type(event[1]) is not str or not re.fullmatch(r"[0-9a-f]{64}", event[1]):
                    raise fail("event_digest_rejected")
                cursor.execute(
                    "SELECT tenant_ref,payload_hash FROM gvai_authority.billing_events WHERE event_id=%s",
                    (event[0],),
                )
                previous = cursor.fetchone()
                if previous is not None:
                    if previous != (tenant, event[1]):
                        raise fail("event_collision_rejected")
                    return False
            cursor.execute("SELECT extract(epoch FROM clock_timestamp())::bigint")
            checked_at = cursor.fetchone()[0]
            cursor.execute("SAVEPOINT billing_snapshot")
            try:
                state = load(pinned)
                self._apply(cursor, tenant, pinned, revoked, state, checked_at)
            except Exception:
                # Commit denial, leave event unacknowledged, and require authoritative retry.
                LOG.warning("stripe_billing: reconciliation_failed_access_suspended")
                cursor.execute("ROLLBACK TO SAVEPOINT billing_snapshot")
                cursor.execute(
                    "UPDATE gvai_authority.billing_customers SET eligible=false,verified_until='-infinity' "
                    "WHERE tenant_ref=%s", (tenant,),
                )
                unavailable = True
            if not unavailable and event is not None:
                cursor.execute(
                    "INSERT INTO gvai_authority.billing_events(event_id,tenant_ref,payload_hash) VALUES(%s,%s,%s)",
                    (event[0], tenant, event[1]),
                )
        if unavailable:
            raise fail("reconciliation_requires_retry")
        return True

    @staticmethod
    def _apply(
        cursor: Any, tenant: int, pinned: str | None, revoked: bool,
        state: PaidState, checked_at: int,
    ) -> None:
        if type(state) is not PaidState:
            raise fail("state_rejected")
        if state.subscription is not None:
            identifier(state.subscription, "sub_")
        if pinned is not None and state.subscription != pinned:
            raise fail("subscription_replacement_rejected")
        invoice = None
        if state.eligible:
            identifier(state.invoice, "in_")
            if (
                state.subscription is None or type(state.start) is not int
                or type(state.end) is not int or type(state.access_until) is not int
                or not state.start <= checked_at < state.access_until <= state.end
            ):
                raise fail("paid_period_rejected")
            cursor.execute(
                "SELECT invoice_id FROM gvai_authority.billing_periods WHERE tenant_ref=%s "
                "AND starts_at<%s AND ends_at>%s AND invoice_id<>%s",
                (tenant, _instant(state.end), _instant(state.start), state.invoice),
            )
            if cursor.fetchone() is not None:
                raise fail("overlapping_period_rejected")
            cursor.execute(
                "INSERT INTO gvai_authority.billing_periods"
                "(invoice_id,tenant_ref,subscription_id,starts_at,ends_at) "
                "VALUES(%s,%s,%s,%s,%s) ON CONFLICT(invoice_id) DO NOTHING",
                (state.invoice, tenant, state.subscription, _instant(state.start), _instant(state.end)),
            )
            cursor.execute(
                "SELECT tenant_ref,subscription_id,starts_at,ends_at,allowance "
                "FROM gvai_authority.billing_periods WHERE invoice_id=%s", (state.invoice,),
            )
            if cursor.fetchone() != (
                tenant, state.subscription, _instant(state.start), _instant(state.end), ALLOWANCE,
            ):
                raise fail("invoice_reassignment_rejected")
            invoice = state.invoice
        cursor.execute(
            "UPDATE gvai_authority.billing_customers SET subscription_id=%s,current_invoice=%s,"
            "eligible=%s,verified_until=%s,access_until=%s WHERE tenant_ref=%s",
            (state.subscription, invoice, state.eligible and not revoked,
             _instant(checked_at + FRESH_SECONDS),
             _instant(state.access_until if state.eligible else 0), tenant),
        )

    def checkout(self, tenant: str, create: Callable[[str], dict[str, Any]]) -> str:
        customer = self.customer(tenant)
        # Persist intent before the external call, including on an uncertain reply.
        with _transaction(self.connect) as cursor:
            self._lock(cursor, customer)
            cursor.execute(
                "UPDATE gvai_authority.billing_customers "
                "SET checkout_started_at=COALESCE(checkout_started_at,clock_timestamp()) "
                "WHERE customer_id=%s", (customer,),
            )
        with _transaction(self.connect) as cursor:
            _, _, revoked = self._lock(cursor, customer)
            cursor.execute(
                "SELECT checkout_session_id,checkout_url,"
                "checkout_started_at>clock_timestamp()-interval '23 hours' "
                "FROM gvai_authority.billing_customers WHERE customer_id=%s", (customer,),
            )
            session_id, url, retryable = cursor.fetchone()
            if revoked or not retryable:
                raise fail("checkout_requires_operator_recovery")
            if session_id is not None:
                return https_url(url, host="checkout.stripe.com")
            value = create(customer)
            identifier(value.get("id"), "cs_test_")
            if (
                value.get("object") != "checkout.session" or value.get("livemode") is not False
                or value.get("customer") != customer or value.get("mode") != "subscription"
            ):
                raise fail("checkout_binding_rejected")
            url = https_url(value.get("url"), host="checkout.stripe.com")
            cursor.execute(
                "UPDATE gvai_authority.billing_customers SET checkout_session_id=%s,checkout_url=%s "
                "WHERE customer_id=%s", (value["id"], url, customer),
            )
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
