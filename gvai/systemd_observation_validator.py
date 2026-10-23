"""Offline-only structural validation for untrusted systemd observations.

Validation never authenticates a manager, authorizes execution or publication,
or establishes effective kernel isolation.
"""

from dataclasses import dataclass
from uuid import UUID

from gvai.systemd_worker_contract import (
    ManagerObservation,
    REQUIRED_RESTRICTIONS,
    WorkerSpec,
    _valid_worker_spec,
)


@dataclass(frozen=True)
class ObservationValidation:
    structurally_valid: bool
    cleanup_complete: bool
    reason: str

    @property
    def authenticated(self) -> bool:
        return False

    @property
    def execution_authorized(self) -> bool:
        return False

    @property
    def runtime_isolation_established(self) -> bool:
        return False

    @property
    def output_publication_authorized(self) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


def _invalid(reason: str) -> ObservationValidation:
    return ObservationValidation(False, False, reason)


def validate_observation(
    observation: object,
    spec: WorkerSpec,
    session: UUID,
    request: UUID,
) -> ObservationValidation:
    """Validate record structure only; UUID correlation is not authentication."""

    if not _valid_worker_spec(spec):
        return _invalid("invalid expected worker specification")
    if (
        type(session) is not UUID or session.int == 0
        or type(request) is not UUID or request.int == 0
    ):
        return _invalid("invalid expected correlation")
    if type(observation) is not ManagerObservation:
        return _invalid("unknown observation")
    if (
        type(observation.session) is not UUID
        or type(observation.request) is not UUID
        or observation.session != session
        or observation.request != request
    ):
        return _invalid("correlation mismatch")
    if (
        not _valid_worker_spec(observation.spec)
        or observation.spec != spec
        or type(observation.service) is not str
        or observation.service != spec.identity.service
    ):
        return _invalid("worker identity mismatch")
    if (
        type(observation.restrictions) is not frozenset
        or observation.restrictions != REQUIRED_RESTRICTIONS
        or type(observation.reaper) is not str
        or observation.reaper != "trusted-manager"
    ):
        return _invalid("unverified restrictions or reaper claim")

    cleanup = (
        observation.kill_requested,
        observation.empty,
        observation.descendants_reaped,
        observation.terminal,
    )
    if any(type(value) is not bool for value in cleanup):
        return _invalid("invalid cleanup fields")
    if not observation.kill_requested:
        return _invalid("STOP not acknowledged")
    if observation.descendants_reaped and not observation.empty:
        return _invalid("reaping contradicts live cgroup population")
    if observation.descendants_reaped and not observation.terminal:
        return _invalid("reaping contradicts nonterminal cleanup")
    if observation.terminal and not (
        observation.empty and observation.descendants_reaped
    ):
        return _invalid("terminal cleanup lacks complete reaping evidence")
    if not observation.terminal:
        return ObservationValidation(True, False, "cleanup still pending")
    return ObservationValidation(True, True, "record structurally complete")
