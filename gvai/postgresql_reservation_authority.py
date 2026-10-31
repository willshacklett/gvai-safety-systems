from __future__ import annotations

import hashlib
from datetime import date
from typing import Callable

from gvai.commercial_api_keys import api_key_credential_material
from gvai.commercial_reservation_authority import (
    AuthorityIdentity,
    AuthorityReceipt,
    CanonicalReservationRequest,
    CommitState,
    EvidenceClass,
    ReservationEvent,
    ReservationResult,
    ReservationStatus,
)


class PostgreSQLAuthorityUnavailable(RuntimeError):
    """The isolated adapter cannot provide authenticated authority-head evidence."""


class PostgreSQLReservationAuthority:
    """Unregistered DB-API adapter for the PostgreSQL reservation schema V1.

    The adapter executes only the restricted V1 reservation routine. Receipts
    are unauthenticated because no production signer or verifier is configured.
    """

    def __init__(
        self,
        connection_factory: Callable[[], object],
        *,
        authority: AuthorityIdentity,
        credential_verifier_secret: bytes,
    ) -> None:
        if not callable(connection_factory):
            raise ValueError("A PostgreSQL connection factory is required.")
        if type(authority) is not AuthorityIdentity:
            raise ValueError("A pinned authority identity is required.")
        if type(credential_verifier_secret) is not bytes or len(credential_verifier_secret) < 32:
            raise ValueError("A separately provisioned credential verifier is required.")
        self._connection_factory = connection_factory
        self._authority = authority
        self._credential_verifier_secret = credential_verifier_secret

    def reserve(
        self,
        request: CanonicalReservationRequest,
        credential: str,
    ) -> ReservationResult:
        if type(request) is not CanonicalReservationRequest:
            return self._denied(ReservationStatus.UNAUTHORIZED)
        credential_material = api_key_credential_material(
            credential, self._credential_verifier_secret
        )
        if credential_material is None:
            return self._denied(ReservationStatus.UNAUTHORIZED)

        key_id, expected_verifier = credential_material
        connection = None
        cursor = None
        commit_attempted = False
        try:
            connection = self._connection_factory()
            connection.autocommit = False
            cursor = connection.cursor()
            cursor.execute(
                """
                SELECT *
                FROM gvai_authority.reserve_v1(
                    %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    key_id,
                    expected_verifier,
                    self._authority.authority_id,
                    self._authority.epoch,
                    self._authority.trust_domain,
                    request.request_id,
                    request.resource_id,
                    request.payload_digest,
                ),
            )
            row = cursor.fetchone()
            if row is None or len(row) != 17:
                return self._rollback_unavailable(connection, CommitState.NOT_COMMITTED)

            try:
                status = ReservationStatus(row[0])
            except (TypeError, ValueError):
                return self._rollback_unavailable(connection, CommitState.NOT_COMMITTED)

            if status in (ReservationStatus.RESERVED, ReservationStatus.REPLAY):
                event = self._event_from_row(row[1:])
                if (
                    event is None
                    or event.request_id_digest != self._digest(request.request_id)
                    or event.request_digest != request.request_digest
                    or event.resource_digest != self._digest(request.resource_id)
                ):
                    return self._rollback_unavailable(connection, CommitState.NOT_COMMITTED)
                receipt = self._receipt(status, event)
                commit_attempted = True
                connection.commit()
                return ReservationResult(status, CommitState.COMMITTED, receipt)

            if status in (
                ReservationStatus.CONFLICT,
                ReservationStatus.QUOTA_EXCEEDED,
                ReservationStatus.UNAUTHORIZED,
            ):
                connection.rollback()
                return self._denied(status)

            connection.rollback()
            return self._unavailable(CommitState.NOT_COMMITTED)
        except Exception:
            rollback_failed = False
            if connection is not None and not commit_attempted:
                try:
                    connection.rollback()
                except Exception:
                    rollback_failed = True
            return self._unavailable(
                CommitState.UNKNOWN
                if commit_attempted or rollback_failed
                else CommitState.NOT_COMMITTED
            )
        finally:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

    def read_authenticated_head(self):
        raise PostgreSQLAuthorityUnavailable(
            "Authenticated authority-head evidence is not configured."
        )

    @staticmethod
    def _denied(status: ReservationStatus) -> ReservationResult:
        return ReservationResult(status, CommitState.NOT_COMMITTED)

    @classmethod
    def _rollback_unavailable(
        cls, connection, commit_state: CommitState
    ) -> ReservationResult:
        connection.rollback()
        return cls._unavailable(commit_state)

    @classmethod
    def _unavailable(cls, commit_state: CommitState) -> ReservationResult:
        return ReservationResult(ReservationStatus.AUTHORITY_UNAVAILABLE, commit_state)

    @staticmethod
    def _receipt(status: ReservationStatus, event: ReservationEvent) -> AuthorityReceipt:
        return AuthorityReceipt(
            authority=event.authority,
            status=status,
            event=event,
            signing_key_id=None,
            signature=None,
            evidence_class=EvidenceClass.UNAUTHENTICATED,
        )

    def _event_from_row(self, row) -> ReservationEvent | None:
        if row is None:
            return None
        (
            authority_id,
            epoch,
            trust_domain,
            sequence,
            event_id,
            previous_event_hash,
            stored_event_hash,
            tenant_digest,
            principal_digest,
            resource_digest,
            request_id_digest,
            request_digest,
            period_start,
            policy_version,
            units,
            contract_version,
        ) = row
        if type(period_start) is not date:
            return None
        if (
            authority_id != self._authority.authority_id
            or epoch != self._authority.epoch
            or trust_domain != self._authority.trust_domain
        ):
            return None
        event = ReservationEvent(
            authority=self._authority,
            sequence=sequence,
            event_id=event_id,
            previous_event_hash=previous_event_hash,
            tenant_digest=tenant_digest,
            principal_digest=principal_digest,
            resource_digest=resource_digest,
            request_id_digest=request_id_digest,
            request_digest=request_digest,
            period=period_start.strftime("%Y-%m"),
            policy_version=policy_version,
            units=units,
            version=contract_version,
        )
        return event if event.event_hash == stored_event_hash else None

    @staticmethod
    def _digest(value: str) -> str:
        return hashlib.sha256(value.encode("ascii")).hexdigest()
