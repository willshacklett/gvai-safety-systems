from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from gvai.commercial_api_keys import (
    ApiKeyOperationError,
    ApiKeyRecord,
    CustomerApiKeys,
    api_key_credential_material,
)
from gvai.commercial_identity import (
    CommercialCapability,
    _valid_customer_tenant,
    _valid_identifier,
)
from gvai.commercial_reservation_authority import (
    AuthorityIdentity,
    CanonicalReservationRequest,
    CommitState,
    MAX_EVALUATION_UNITS,
    ReservationStatus,
)
from gvai.commercial_usage import UsageReason, UsageReservation, UsageResult
from gvai.postgresql_reservation_authority import PostgreSQLReservationAuthority


ConnectionFactory = Callable[[], Any]


class PostgreSQLCustomerStore:
    """Trusted operator/key-verifier adapter, never a customer request interface.

    Supply a separately controlled provisioning connection. The evaluation
    runtime must not receive these credentials or any table-write privileges.
    """

    def __init__(self, connection_factory: ConnectionFactory) -> None:
        if not callable(connection_factory):
            raise ValueError("A provisioning connection factory is required.")
        self._connect = connection_factory

    def provision_pilot(
        self, *, tenant_id: str, principal_id: str, resource_id: str,
        allowance: int, starts_at: int, expires_at: int,
    ) -> None:
        """Create a new invite-only pilot atomically; never reset existing usage."""
        if (
            not _valid_customer_tenant(tenant_id)
            or not _valid_identifier(principal_id)
            or not _valid_identifier(resource_id)
            or type(allowance) is not int or not 0 <= allowance <= MAX_EVALUATION_UNITS
            or type(starts_at) is not int or type(expires_at) is not int
            or not 0 <= starts_at < expires_at
        ):
            raise ApiKeyOperationError("Invalid pilot provisioning input.")
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO gvai_authority.tenants (tenant_id,status) "
                    "VALUES (%s,'active') RETURNING tenant_ref", (tenant_id,),
                )
                tenant_ref = cursor.fetchone()[0]
                cursor.execute(
                    "INSERT INTO gvai_authority.tenant_memberships (tenant_ref,principal_id,status) "
                    "VALUES (%s,%s,'active')", (tenant_ref, principal_id),
                )
                cursor.execute(
                    "INSERT INTO gvai_authority.resource_ownerships "
                    "(tenant_ref,resource_id,ownership_version,resource_kind,status) "
                    "VALUES (%s,%s,1,'evaluation','active')", (tenant_ref, resource_id),
                )
                cursor.execute(
                    "INSERT INTO gvai_authority.quota_policies "
                    "(tenant_ref,policy_version,monthly_allowance) VALUES (%s,'advisory-pilot-v1',%s)",
                    (tenant_ref, allowance),
                )
                cursor.execute(
                    "INSERT INTO gvai_authority.current_quota_policies "
                    "(tenant_ref,policy_version) VALUES (%s,'advisory-pilot-v1')", (tenant_ref,),
                )
                cursor.execute(
                    "INSERT INTO gvai_authority.advisory_pilots "
                    "(tenant_ref,allowance,starts_at,expires_at) VALUES (%s,%s,%s,%s)",
                    (tenant_ref, allowance, datetime.fromtimestamp(starts_at, timezone.utc),
                     datetime.fromtimestamp(expires_at, timezone.utc)),
                )
        except Exception as error:
            raise ApiKeyOperationError("Pilot provisioning failed; reconcile before retry.") from error

    def insert_if_absent(self, record: ApiKeyRecord) -> bool:
        if (
            type(record) is not ApiKeyRecord or record.revoked
            or not CustomerApiKeys._valid_record(record, record.key_id)
        ):
            raise ApiKeyOperationError("Invalid API key record.")
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO gvai_authority.customer_credentials
                    (key_id,tenant_ref,membership_ref,credential_verifier,capabilities,
                     status,created_at,expires_at)
                SELECT %s, tenant.tenant_ref, membership.membership_ref, %s, %s,
                       'active', %s, %s
                FROM gvai_authority.tenants AS tenant
                JOIN gvai_authority.tenant_memberships AS membership
                  ON membership.tenant_ref=tenant.tenant_ref
                WHERE tenant.tenant_id=%s AND membership.principal_id=%s
                  AND tenant.status='active' AND membership.status='active'
                ON CONFLICT (key_id) DO NOTHING RETURNING key_id
                """,
                (record.key_id, record.verifier, sorted(grant.value for grant in record.capabilities),
                 datetime.fromtimestamp(record.created_at, timezone.utc),
                 datetime.fromtimestamp(record.expires_at, timezone.utc),
                 record.tenant_id, record.principal_id),
            )
            inserted = cursor.fetchone() is not None
        return inserted

    def lookup(self, key_id: str) -> ApiKeyRecord | None:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT credential.key_id,membership.principal_id,tenant.tenant_id,
                       credential.capabilities,credential.created_at,credential.expires_at,
                       credential.credential_verifier,
                       (credential.status <> 'active' OR tenant.status <> 'active'
                        OR membership.status <> 'active')
                FROM gvai_authority.customer_credentials AS credential
                JOIN gvai_authority.tenants AS tenant ON tenant.tenant_ref=credential.tenant_ref
                JOIN gvai_authority.tenant_memberships AS membership
                  ON membership.tenant_ref=credential.tenant_ref
                 AND membership.membership_ref=credential.membership_ref
                WHERE credential.key_id=%s
                """, (key_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return ApiKeyRecord(
            row[0], row[1], row[2], frozenset(CommercialCapability(value) for value in row[3]),
            int(row[4].timestamp()), int(row[5].timestamp()), bytes(row[6]), row[7],
        )

    def revoke(self, key_id: str) -> bool:
        with self._connect() as connection, connection.cursor() as cursor:
            cursor.execute(
                "UPDATE gvai_authority.customer_credentials SET status='revoked', "
                "revoked_at=COALESCE(revoked_at,clock_timestamp()) "
                "WHERE key_id=%s RETURNING key_id", (key_id,),
            )
            revoked = cursor.fetchone() is not None
        return revoked


class _AdvisoryReservationAdapter(PostgreSQLReservationAuthority):
    _RESERVATION_SQL = """
        SELECT * FROM gvai_authority.reserve_advisory_v1(
            %s, %s, %s, %s, %s, %s, %s, %s
        )
    """


@dataclass(frozen=True)
class AdvisoryPilotUsage:
    allowance: int
    consumed: int
    reserved: int
    completed: int
    failed: int

    @property
    def remaining(self) -> int:
        return self.allowance - self.consumed


class AdvisoryAccountingUnavailable(RuntimeError):
    """Advisory accounting read/completion is unavailable or ambiguous."""


class PostgreSQLAdvisoryUsage:
    """Direct trusted-DB accounting ONLY for advisory evaluation.

    This is not CommercialUsage promotion and never verifies or emits signed
    execution grants. Existing unsigned-receipt and SQLite gates are unchanged.
    Committed attempts are charged even when evaluation/completion fails.
    """

    def __init__(
        self, connection_factory: ConnectionFactory, *, authority: AuthorityIdentity,
        credential_verifier_secret: bytes,
    ) -> None:
        self._adapter = _AdvisoryReservationAdapter(
            connection_factory, authority=authority,
            credential_verifier_secret=credential_verifier_secret,
        )
        self._connect = connection_factory
        self._secret = credential_verifier_secret

    def reserve_evaluation(
        self, credential: object, resource_id: str, request_id: str, payload: bytes
    ) -> UsageResult:
        try:
            request = CanonicalReservationRequest.from_bounded_input(request_id, resource_id, payload)
        except ValueError:
            return UsageResult(UsageReason.INVALID_INPUT)
        result = self._adapter.reserve(request, credential)
        if result.status is ReservationStatus.RESERVED:
            if result.commit_state is not CommitState.COMMITTED or result.receipt is None:
                return UsageResult(UsageReason.ACCOUNTING_ERROR)
            return UsageResult(
                UsageReason.RESERVED,
                UsageReservation(result.receipt.event.period, result.receipt.event.resource_digest),
            )
        return UsageResult({
            ReservationStatus.REPLAY: UsageReason.REPLAY,
            ReservationStatus.CONFLICT: UsageReason.CONFLICT,
            ReservationStatus.QUOTA_EXCEEDED: UsageReason.QUOTA_EXHAUSTED,
            ReservationStatus.UNAUTHORIZED: UsageReason.UNAUTHORIZED,
            ReservationStatus.AUTHORITY_UNAVAILABLE: UsageReason.ACCOUNTING_ERROR,
        }[result.status])

    def complete(
        self, credential: object, resource_id: str, request_id: str, *, succeeded: bool,
    ) -> UsageResult:
        material = api_key_credential_material(credential, self._secret)
        if material is None:
            return UsageResult(UsageReason.UNAUTHORIZED)
        if not _valid_identifier(resource_id) or not _valid_identifier(request_id) or type(succeeded) is not bool:
            return UsageResult(UsageReason.INVALID_INPUT)
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT gvai_authority.complete_advisory_v1(%s,%s,%s,%s,%s)",
                    (*material, resource_id, request_id, succeeded),
                )
                row = cursor.fetchone()
                reason = UsageReason(row[0]) if row is not None else UsageReason.ACCOUNTING_ERROR
        except Exception as error:
            raise AdvisoryAccountingUnavailable("Advisory completion unavailable; unit remains charged.") from error
        return UsageResult(reason)

    def summary(self, credential: object, resource_id: str) -> AdvisoryPilotUsage | None:
        material = api_key_credential_material(credential, self._secret)
        if material is None or not _valid_identifier(resource_id):
            return None
        try:
            with self._connect() as connection, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM gvai_authority.advisory_usage_v1(%s,%s,%s)",
                    (*material, resource_id),
                )
                row = cursor.fetchone()
        except Exception as error:
            raise AdvisoryAccountingUnavailable("Advisory usage summary unavailable.") from error
        if row is None:
            return None
        if (
            len(row) != 5 or any(type(value) is not int or value < 0 for value in row)
            or row[1] > row[0] or sum(row[2:]) != row[1]
        ):
            raise AdvisoryAccountingUnavailable("Advisory usage evidence inconsistent.")
        return AdvisoryPilotUsage(*row)
