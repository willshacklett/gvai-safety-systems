from __future__ import annotations

import math
import threading
import time
from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol

from gvai.commercial_reservation_authority import AuthorityIdentity
from gvai.experimental_authority_head import (
    AuthorityHeadCheckpoint,
    AuthorityHeadState,
    ExperimentalAuthorityHeadVerifier,
)


class CheckpointStorageError(RuntimeError):
    """Unavailable, corrupt, or ambiguous storage; never an acceptance."""


class DurableCheckpointStorage(Protocol):
    """Independent, authenticated, linearizable storage boundary.

    Provisioning is external: neither operation may create missing trust state.
    Read the complete signed record for the exact authority. Compare-and-swap
    must atomically compare the complete expected record, reject identity
    changes, sequence regression and equal-sequence hash conflicts, and durably
    commit before returning True. False means ONLY a clean comparison loss.
    Ambiguous commits, corruption and outages raise CheckpointStorageError.
    Enforce the supplied deadline, authenticate transport/responses, and keep
    custody and backup/recovery independent of PostgreSQL and checkpoint keys.
    A local file or process-local implementation does not satisfy independence.
    """

    def read_checkpoint(
        self, authority: AuthorityIdentity, *, timeout_seconds: float
    ) -> AuthorityHeadCheckpoint | None: ...

    def compare_and_swap(
        self,
        expected: AuthorityHeadCheckpoint,
        candidate: AuthorityHeadCheckpoint,
        *,
        timeout_seconds: float,
    ) -> bool: ...


def _snapshot(checkpoint: object) -> AuthorityHeadCheckpoint:
    if (
        type(checkpoint) is not AuthorityHeadCheckpoint
        or type(checkpoint.head) is not AuthorityHeadState
        or type(checkpoint.head.authority) is not AuthorityIdentity
    ):
        raise ValueError("Invalid checkpoint record.")
    return replace(
        checkpoint,
        head=replace(checkpoint.head, authority=replace(checkpoint.head.authority)),
    )


def _at_least(candidate: AuthorityHeadState, floor: AuthorityHeadState) -> bool:
    return candidate.authority == floor.authority and (
        candidate.sequence > floor.sequence
        or (candidate.sequence == floor.sequence and candidate.event_hash == floor.event_hash)
    )


def _deadline(timeout_seconds: float) -> float:
    if (
        type(timeout_seconds) not in (int, float)
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 30
    ):
        raise ValueError("Checkpoint timeout must be bounded and positive.")
    return time.monotonic() + timeout_seconds


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise CheckpointStorageError("storage_timeout")
    return remaining


class ExperimentalDurableHighWaterProvider:
    """Authenticated CAS foundation, conditional on trusted storage guarantees.

    The separately provisioned signed recovery anchor is a lower bound, not a
    current-tip oracle. No credentials, production adapter or bootstrap exists.
    """

    __slots__ = ("_storage", "_verifier", "_anchor")

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("Checkpoint recovery trust configuration is immutable.")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Checkpoint recovery trust configuration is immutable.")

    def __init__(
        self,
        *,
        storage: DurableCheckpointStorage,
        signature_verifier: ExperimentalAuthorityHeadVerifier,
        recovery_anchor: AuthorityHeadCheckpoint,
    ) -> None:
        if type(signature_verifier) is not ExperimentalAuthorityHeadVerifier:
            raise ValueError("A pinned checkpoint signature verifier is required.")
        if not all(callable(getattr(storage, name, None)) for name in (
            "read_checkpoint", "compare_and_swap"
        )):
            raise ValueError("A durable checkpoint storage adapter is required.")
        anchor = _snapshot(recovery_anchor)
        if not signature_verifier.verify_signature(anchor):
            raise ValueError("Recovery anchor must authenticate against pinned keys.")
        self._storage = storage
        self._verifier = signature_verifier
        self._anchor = anchor

    def _authenticate(self, checkpoint: object) -> AuthorityHeadCheckpoint:
        try:
            snapshot = _snapshot(checkpoint)
        except (AttributeError, TypeError, ValueError) as error:
            raise CheckpointStorageError("stored_checkpoint_malformed") from error
        if not self._verifier.verify_signature(snapshot):
            raise CheckpointStorageError("checkpoint_signature_invalid")
        return snapshot

    def _read(self, deadline: float) -> AuthorityHeadCheckpoint:
        record = self._storage.read_checkpoint(
            replace(self._anchor.head.authority), timeout_seconds=_remaining(deadline)
        )
        _remaining(deadline)
        if record is None:
            raise CheckpointStorageError("missing_trust_state")
        current = self._authenticate(record)
        if not _at_least(current.head, self._anchor.head):
            raise CheckpointStorageError("storage_below_recovery_anchor_or_conflicting")
        return current

    def read_verified_checkpoint(
        self, *, timeout_seconds: float
    ) -> AuthorityHeadCheckpoint:
        return self._read(_deadline(timeout_seconds))

    def _swap(
        self,
        current: AuthorityHeadCheckpoint,
        candidate: AuthorityHeadCheckpoint,
        deadline: float,
    ) -> bool:
        expected_copy = _snapshot(current)
        candidate_copy = _snapshot(candidate)
        result = self._storage.compare_and_swap(
            expected_copy, candidate_copy, timeout_seconds=_remaining(deadline)
        )
        _remaining(deadline)
        try:
            returned_expected = self._authenticate(expected_copy)
            returned_candidate = self._authenticate(candidate_copy)
        except CheckpointStorageError as error:
            raise CheckpointStorageError("storage_argument_substitution") from error
        if returned_expected != current or returned_candidate != candidate:
            raise CheckpointStorageError("storage_argument_substitution")
        if type(result) is not bool:
            raise CheckpointStorageError("ambiguous_storage_response")
        return result

    def check_and_advance(
        self, checkpoint: AuthorityHeadCheckpoint, *, timeout_seconds: float
    ) -> AuthorityHeadState | None:
        deadline = _deadline(timeout_seconds)
        candidate = self._authenticate(checkpoint)
        for _ in range(16):
            current = self._read(deadline)
            if not _at_least(candidate.head, current.head):
                return None
            if self._swap(current, candidate, deadline):
                return replace(candidate.head, authority=replace(candidate.head.authority))
        raise CheckpointStorageError("storage_contention")

    def confirm_current(
        self, checkpoint: AuthorityHeadCheckpoint, *, timeout_seconds: float
    ) -> bool:
        """Reconciliation never advances storage from database or caller input."""
        deadline = _deadline(timeout_seconds)
        candidate = self._authenticate(checkpoint)
        current = self._read(deadline)
        if candidate.head != current.head:
            return False
        return self._swap(current, current, deadline)


class CheckpointRecoveryState(str, Enum):
    FENCED = "fenced"
    MATCHED = "matched"
    RECONCILED = "reconciled"


@dataclass(frozen=True)
class CheckpointRecoveryAssessment:
    state: CheckpointRecoveryState
    reason: str


class ExperimentalCheckpointRecoveryFence:
    """Offline assessment only; no service reopening or execution authority.

    Each assessment is point-in-time. Reconciliation is explicit and never
    survives reconstruction. Call check_reconciled with fresh trusted database
    evidence before further recovery work; it rechecks storage atomically.
    """

    def __init__(
        self, provider: ExperimentalDurableHighWaterProvider, *, timeout_seconds: float = 2.0
    ) -> None:
        if type(provider) is not ExperimentalDurableHighWaterProvider:
            raise ValueError("An experimental durable high-water provider is required.")
        _deadline(timeout_seconds)
        self._provider = provider
        self._timeout = float(timeout_seconds)
        self._lock = threading.Lock()
        self._reconciled: AuthorityHeadCheckpoint | None = None
        self._assessment = CheckpointRecoveryAssessment(
            CheckpointRecoveryState.FENCED, "explicit_reconciliation_required"
        )

    @property
    def assessment(self) -> CheckpointRecoveryAssessment:
        with self._lock:
            return self._assessment

    @property
    def may_authorize_fresh_grant(self) -> bool:
        return False

    def _finish(self, state: CheckpointRecoveryState, reason: str) -> CheckpointRecoveryAssessment:
        self._assessment = CheckpointRecoveryAssessment(state, reason)
        if state is not CheckpointRecoveryState.RECONCILED:
            self._reconciled = None
        return self._assessment

    def _match(
        self, checkpoint: object, database_head: object
    ) -> AuthorityHeadCheckpoint:
        candidate = self._provider._authenticate(checkpoint)
        if (
            type(database_head) is not AuthorityHeadState
            or type(database_head.authority) is not AuthorityIdentity
        ):
            raise CheckpointStorageError("database_head_missing_or_ambiguous")
        try:
            observed = replace(database_head, authority=replace(database_head.authority))
        except (AttributeError, TypeError, ValueError) as error:
            raise CheckpointStorageError("database_head_malformed") from error
        if observed != candidate.head:
            raise CheckpointStorageError("database_checkpoint_mismatch")
        if not self._provider.confirm_current(candidate, timeout_seconds=self._timeout):
            raise CheckpointStorageError("stored_head_mismatch_or_concurrent_change")
        return candidate

    def assess(
        self, checkpoint: object, database_head: object
    ) -> CheckpointRecoveryAssessment:
        with self._lock:
            self._finish(CheckpointRecoveryState.FENCED, "assessment_in_progress")
            try:
                self._match(checkpoint, database_head)
            except CheckpointStorageError as error:
                return self._finish(CheckpointRecoveryState.FENCED, str(error))
            return self._finish(CheckpointRecoveryState.MATCHED, "explicit_reconciliation_required")

    def reconcile(
        self, checkpoint: object, database_head: object
    ) -> CheckpointRecoveryAssessment:
        with self._lock:
            self._finish(CheckpointRecoveryState.FENCED, "reconciliation_in_progress")
            try:
                candidate = self._match(checkpoint, database_head)
            except CheckpointStorageError as error:
                return self._finish(CheckpointRecoveryState.FENCED, str(error))
            self._reconciled = candidate
            return self._finish(CheckpointRecoveryState.RECONCILED, "heads_reconciled_no_grant_authority")

    def check_reconciled(self, database_head: object) -> CheckpointRecoveryAssessment:
        with self._lock:
            if self._reconciled is None:
                return self._finish(CheckpointRecoveryState.FENCED, "explicit_reconciliation_required")
            candidate = self._reconciled
            self._finish(CheckpointRecoveryState.FENCED, "revalidation_in_progress")
            try:
                self._match(candidate, database_head)
            except CheckpointStorageError as error:
                return self._finish(CheckpointRecoveryState.FENCED, str(error))
            self._reconciled = candidate
            return self._finish(CheckpointRecoveryState.RECONCILED, "heads_reconciled_no_grant_authority")
