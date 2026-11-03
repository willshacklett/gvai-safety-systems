from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from gvai.commercial_usage import SQLiteUsageStore


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class RecoveryState(str, Enum):
    UNVERIFIED = "unverified"
    READY = "ready"
    REBUILD_REQUIRED = "rebuild_required"
    QUARANTINED = "quarantined"
    DENIED = "denied"


@dataclass(frozen=True)
class TrustedHead:
    authority_id: str
    sequence: int
    digest: str
    authenticated: bool


@dataclass(frozen=True)
class ProjectionHead:
    sequence: int
    digest: str


class TrustedHeadProvider(Protocol):
    """Trusted adapter; returned heads must be authenticated independently."""

    def read_verified_head(self) -> TrustedHead: ...


class ProjectionHeadReader(Protocol):
    """Read the current projection cursor; never infer it from ledger rows."""

    def read_projection_head(self, store: SQLiteUsageStore) -> ProjectionHead | None: ...


class SQLiteRecoveryGate:
    """Offline recovery assessment only; never authorizes an evaluation grant.

    The current SQLite schema has no projection sequence/hash, so the default
    reader is absent and valid existing databases require trusted rebuilding.
    No production trusted-head or projection reader is supplied here.
    """

    def __init__(
        self,
        store: SQLiteUsageStore,
        *,
        expected_authority_id: str | None,
        trusted_head_provider: TrustedHeadProvider | None = None,
        projection_reader: ProjectionHeadReader | None = None,
    ) -> None:
        self._store = store
        self._expected_authority_id = expected_authority_id
        self._trusted_head_provider = trusted_head_provider
        self._projection_reader = projection_reader
        self._state = RecoveryState.UNVERIFIED
        self._reason = "not_verified"

    @property
    def state(self) -> RecoveryState:
        return self._state

    @property
    def reason(self) -> str:
        return self._reason

    @property
    def may_authorize_fresh_grant(self) -> bool:
        return False

    def verify(self) -> RecoveryState:
        self._state = RecoveryState.UNVERIFIED
        self._reason = "verification_in_progress"

        try:
            self._store.verify_recovery_integrity()
        except Exception:
            return self._finish(RecoveryState.QUARANTINED, "sqlite_evidence_invalid")

        if (
            type(self._expected_authority_id) is not str
            or not self._expected_authority_id
            or self._trusted_head_provider is None
        ):
            return self._finish(RecoveryState.DENIED, "trusted_authority_missing")

        try:
            head = self._trusted_head_provider.read_verified_head()
        except Exception:
            return self._finish(RecoveryState.DENIED, "trusted_authority_unavailable")

        if not self._valid_head(head):
            return self._finish(RecoveryState.QUARANTINED, "trusted_head_invalid")
        if head.authority_id != self._expected_authority_id:
            return self._finish(RecoveryState.QUARANTINED, "authority_identity_mismatch")

        if self._projection_reader is None:
            return self._finish(RecoveryState.REBUILD_REQUIRED, "projection_head_missing")
        try:
            projection = self._projection_reader.read_projection_head(self._store)
        except Exception:
            return self._finish(RecoveryState.DENIED, "projection_unavailable")
        if projection is None:
            return self._finish(RecoveryState.REBUILD_REQUIRED, "projection_head_missing")
        if not self._valid_projection(projection):
            return self._finish(RecoveryState.QUARANTINED, "projection_head_invalid")
        if projection.sequence < head.sequence:
            return self._finish(RecoveryState.REBUILD_REQUIRED, "projection_behind_authority")
        if projection.sequence > head.sequence:
            return self._finish(RecoveryState.QUARANTINED, "projection_ahead_of_authority")
        if projection.digest != head.digest:
            return self._finish(RecoveryState.QUARANTINED, "projection_digest_mismatch")

        return self._finish(RecoveryState.READY, "recovery_heads_match_no_grant_authority")

    def _finish(self, state: RecoveryState, reason: str) -> RecoveryState:
        self._state = state
        self._reason = reason
        return state

    @staticmethod
    def _valid_head(head: object) -> bool:
        return (
            type(head) is TrustedHead
            and type(head.authority_id) is str
            and bool(head.authority_id)
            and type(head.sequence) is int
            and head.sequence >= 0
            and type(head.digest) is str
            and _DIGEST.fullmatch(head.digest) is not None
            and type(head.authenticated) is bool
            and head.authenticated is True
        )

    @staticmethod
    def _valid_projection(projection: object) -> bool:
        return (
            type(projection) is ProjectionHead
            and type(projection.sequence) is int
            and projection.sequence >= 0
            and type(projection.digest) is str
            and _DIGEST.fullmatch(projection.digest) is not None
        )
