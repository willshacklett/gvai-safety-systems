"""Dormant launcher lifecycle model; no runtime verifier or execution authority."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import threading
from typing import Protocol
from uuid import UUID

from gvai.systemd_worker_contract import WorkerSpec, _valid_worker_spec
from gvai.systemd_worker_profile import WORKER_APPARMOR_PROFILE, WORKER_SECCOMP_POLICY_ID


SETUP_APPARMOR_PROFILE = "gvai-setup"
PROPOSED_WORKER_LABEL = f"{SETUP_APPARMOR_PROFILE}//&{WORKER_APPARMOR_PROFILE}"


class LifecycleState(Enum):
    STOPPED = "STOPPED"
    SETUP_PENDING = "SETUP_PENDING"
    SETUP_CONFINED = "SETUP_CONFINED"
    NAMESPACES_ESTABLISHED = "NAMESPACES_ESTABLISHED"
    INPUT_AND_SECCOMP_VERIFIED = "INPUT_AND_SECCOMP_VERIFIED"
    WORKER_CONFINEMENT_VERIFIED = "WORKER_CONFINEMENT_VERIFIED"
    READY_FOR_SEPARATE_RUNTIME_AUTHORIZATION = "READY_FOR_SEPARATE_RUNTIME_AUTHORIZATION"
    TERMINATION_PENDING = "TERMINATION_PENDING"
    TERMINATED = "TERMINATED"
    FAILED_CLOSED = "FAILED_CLOSED"


class EvidenceRequirement(Enum):
    MANAGER_AUTHORIZED_FIXED_UNIT = "manager-authorized-fixed-unit"
    TRUSTED_LAUNCHER_IDENTITY = "trusted-launcher-identity"
    SETUP_PROFILE_ENFORCING = "setup-profile-enforcing"
    NAMESPACES = "user-pid-mount-network-uts-ipc-identities"
    UID_MAPS = "both-uid-gid-map-stages-and-connected-procfs"
    PINNED_INPUT = "race-resistant-input-descriptor-identity"
    READONLY_MOUNTS = "readonly-root-runtime-input-no-host-writable-mount"
    BOUNDED_SCRATCH = "private-scratch-tmpfs-exact-size-and-mode"
    CGROUP = "dedicated-cgroup-v2-device-inode-and-limits"
    SECCOMP = f"installed-{WORKER_SECCOMP_POLICY_ID}-trusted-descriptor"
    NO_NEW_PRIVILEGES = "no-new-privileges"
    ZERO_CAPABILITIES = "all-five-capability-sets-empty"
    DESCRIPTOR_ISOLATION = "no-manager-stop-publication-setup-or-unauthorized-fds"
    REAPER = "trusted-private-pid-namespace-reaper"
    EXTERNAL_TERMINATION = "manager-outside-containment-and-loss-cleanup"
    WORKER_PROFILE_ENFORCING = "exact-worker-stack-enforcing-before-untrusted-code"
    NO_SETUP_AUTHORITY = "no-effective-launcher-manager-stop-or-publication-authority"
    KERNEL_TRANSITION = "reviewed-target-kernel-transition-acceptance"
    STOP_LATCHED = "external-durable-stop-latched"
    KILL_REQUESTED = "external-whole-cgroup-termination-requested"
    CGROUP_EMPTY = "pinned-worker-cgroup-empty"
    DESCENDANTS_REAPED = "all-descendants-reaped"


_SETUP = frozenset({
    EvidenceRequirement.MANAGER_AUTHORIZED_FIXED_UNIT,
    EvidenceRequirement.TRUSTED_LAUNCHER_IDENTITY,
    EvidenceRequirement.SETUP_PROFILE_ENFORCING,
    EvidenceRequirement.NO_NEW_PRIVILEGES,
    EvidenceRequirement.CGROUP,
    EvidenceRequirement.EXTERNAL_TERMINATION,
})
_NAMESPACES = _SETUP | {
    EvidenceRequirement.NAMESPACES, EvidenceRequirement.UID_MAPS,
    EvidenceRequirement.REAPER,
}
_INPUT = _NAMESPACES | {
    EvidenceRequirement.PINNED_INPUT, EvidenceRequirement.READONLY_MOUNTS,
    EvidenceRequirement.BOUNDED_SCRATCH, EvidenceRequirement.SECCOMP,
    EvidenceRequirement.DESCRIPTOR_ISOLATION,
}
_WORKER = _INPUT | {
    EvidenceRequirement.WORKER_PROFILE_ENFORCING,
    EvidenceRequirement.NO_SETUP_AUTHORITY, EvidenceRequirement.KERNEL_TRANSITION,
    EvidenceRequirement.NO_NEW_PRIVILEGES, EvidenceRequirement.ZERO_CAPABILITIES,
}
_CLEANUP = frozenset({
    EvidenceRequirement.STOP_LATCHED, EvidenceRequirement.KILL_REQUESTED,
    EvidenceRequirement.CGROUP_EMPTY, EvidenceRequirement.DESCENDANTS_REAPED,
    EvidenceRequirement.CGROUP, EvidenceRequirement.EXTERNAL_TERMINATION,
})


def required_evidence(state: LifecycleState) -> frozenset[EvidenceRequirement]:
    """Cumulative requirements, not assertions that any requirement is satisfied."""
    if type(state) is not LifecycleState:
        raise ValueError("An exact lifecycle state is required.")
    return {
        LifecycleState.SETUP_CONFINED: _SETUP,
        LifecycleState.NAMESPACES_ESTABLISHED: _NAMESPACES,
        LifecycleState.INPUT_AND_SECCOMP_VERIFIED: _INPUT,
        LifecycleState.WORKER_CONFINEMENT_VERIFIED: _WORKER,
        LifecycleState.READY_FOR_SEPARATE_RUNTIME_AUTHORIZATION: _WORKER,
        LifecycleState.TERMINATED: _CLEANUP,
    }.get(state, frozenset())


def termination_target(state: LifecycleState) -> LifecycleState:
    """STOP preempts every phase, including currently unreachable model states."""
    if type(state) is not LifecycleState:
        raise ValueError("An exact lifecycle state is required.")
    return (
        LifecycleState.TERMINATED if state is LifecycleState.TERMINATED
        else LifecycleState.TERMINATION_PENDING
    )


@dataclass(frozen=True)
class EvidenceRequest:
    spec: WorkerSpec
    session: UUID
    revision: int
    previous: LifecycleState
    target: LifecycleState


@dataclass(frozen=True)
class EvidenceAssessment:
    """Verifier response, not a transferable credential or kernel attestation."""

    request: EvidenceRequest
    checks: frozenset[EvidenceRequirement]
    apparmor_label: str


class TrustedLifecycleVerifier(Protocol):
    """Supervisor-owned TCB interface. No production implementation exists here.

    Implementations must independently authenticate and freshly observe the exact
    process, attempt, boot, cgroup, limits and artifacts in the request. A worker
    supplied assessment or boolean must never be echoed back as verification.
    """

    def verify(
        self, request: EvidenceRequest, evidence: object,
    ) -> EvidenceAssessment: ...


@dataclass(frozen=True)
class LifecycleReport:
    state: LifecycleState
    revision: int
    stop_requested: bool
    errors: tuple[str, ...]

    @property
    def runtime_verified(self) -> bool:
        return False

    @property
    def execution_authorized(self) -> bool:
        return False

    @property
    def output_publication_authorized(self) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


_NEXT = {
    LifecycleState.STOPPED: LifecycleState.SETUP_PENDING,
    LifecycleState.SETUP_PENDING: LifecycleState.SETUP_CONFINED,
    LifecycleState.SETUP_CONFINED: LifecycleState.NAMESPACES_ESTABLISHED,
    LifecycleState.NAMESPACES_ESTABLISHED: LifecycleState.INPUT_AND_SECCOMP_VERIFIED,
    LifecycleState.INPUT_AND_SECCOMP_VERIFIED: LifecycleState.WORKER_CONFINEMENT_VERIFIED,
    LifecycleState.WORKER_CONFINEMENT_VERIFIED:
        LifecycleState.READY_FOR_SEPARATE_RUNTIME_AUTHORIZATION,
    LifecycleState.TERMINATION_PENDING: LifecycleState.TERMINATED,
}


class LauncherWorkerContract:
    """Single-owner, stop-only model. Injected fixtures cannot unblock worker entry."""

    def __init__(
        self, spec: WorkerSpec, session: UUID,
        verifier: TrustedLifecycleVerifier | None = None,
    ):
        if (
            not _valid_worker_spec(spec)
            or type(session) is not UUID or session.int == 0
        ):
            raise ValueError("A fixed worker specification and nonzero session are required.")
        self._spec = spec
        self._session = session
        self._verifier = verifier
        self._state = LifecycleState.STOPPED
        self._revision = 0
        self._stop_requested = False
        self._errors: tuple[str, ...] = ()
        self._lock = threading.Lock()

    def _report(self) -> LifecycleReport:
        return LifecycleReport(
            self._state, self._revision, self._stop_requested, self._errors,
        )

    def snapshot(self) -> LifecycleReport:
        with self._lock:
            return self._report()

    def request_for(self, target: LifecycleState) -> EvidenceRequest:
        with self._lock:
            if type(target) is not LifecycleState:
                raise ValueError("An exact target lifecycle state is required.")
            return EvidenceRequest(
                self._spec, self._session, self._revision, self._state, target,
            )

    def _fail(self, reason: str) -> LifecycleReport:
        self._state = LifecycleState.FAILED_CLOSED
        self._errors = (*self._errors, reason)
        return self._report()

    def advance(
        self, target: LifecycleState, evidence: object = None,
    ) -> LifecycleReport:
        with self._lock:
            request = EvidenceRequest(
                self._spec, self._session, self._revision, self._state, target,
            )
            self._revision += 1
            if type(target) is not LifecycleState or _NEXT.get(self._state) is not target:
                return self._fail("Skipped, repeated, terminal or invalid lifecycle transition.")
            if self._stop_requested and target is not LifecycleState.TERMINATED:
                return self._fail("STOP is latched; setup and worker entry remain denied.")
            if target is LifecycleState.SETUP_PENDING:
                self._state = target
                return self._report()
            if self._verifier is None:
                return self._fail("Independent trusted runtime verifier is not implemented.")

            # An unexpected verifier exception must also leave the contract stopped.
            self._state = LifecycleState.FAILED_CLOSED
            self._errors = (*self._errors, "Evidence verification did not complete.")
            epoch = self._revision
            verifier = self._verifier

        # Neither verification nor interpretation of external evidence may delay STOP.
        try:
            assessment = verifier.verify(request, evidence)
            failure = self._assessment_failure(request, assessment)
        except (OSError, ValueError, TypeError, RuntimeError) as error:
            failure = f"Evidence verification failed: {type(error).__name__}: {error}"

        with self._lock:
            if self._revision != epoch:
                return self._report()
            if failure is not None:
                return self._fail(failure)
            self._errors = self._errors[:-1]
            self._state = target
            return self._report()

    @staticmethod
    def _assessment_failure(
        request: EvidenceRequest, assessment: EvidenceAssessment,
    ) -> str | None:
        target = request.target
        if (
            type(assessment) is not EvidenceAssessment
            or type(assessment.request) is not EvidenceRequest
            or not _valid_worker_spec(assessment.request.spec)
            or type(assessment.request.session) is not UUID
            or type(assessment.request.revision) is not int
            or type(assessment.request.previous) is not LifecycleState
            or type(assessment.request.target) is not LifecycleState
            or assessment.request != request
            or type(assessment.checks) is not frozenset
            or any(type(check) is not EvidenceRequirement for check in assessment.checks)
            or not required_evidence(target) <= assessment.checks
        ):
            return "Missing, forged, stale or incorrectly bound evidence."
        if target is not LifecycleState.TERMINATED:
            expected_label = (
                PROPOSED_WORKER_LABEL if target in (
                    LifecycleState.WORKER_CONFINEMENT_VERIFIED,
                    LifecycleState.READY_FOR_SEPARATE_RUNTIME_AUTHORIZATION,
                ) else SETUP_APPARMOR_PROFILE
            )
            if (
                type(assessment.apparmor_label) is not str
                or assessment.apparmor_label != expected_label
            ):
                return "Wrong AppArmor attachment; exact enforcing label required."
        if target in (
            LifecycleState.WORKER_CONFINEMENT_VERIFIED,
            LifecycleState.READY_FOR_SEPARATE_RUNTIME_AUTHORIZATION,
        ):
            return "Target-kernel AppArmor transition remains unreviewed and unverified."
        return None

    def request_stop(self) -> LifecycleReport:
        """Record termination intent only; does not signal, reap or persist STOP."""
        with self._lock:
            self._revision += 1
            self._stop_requested = True
            self._state = termination_target(self._state)
            return self._report()
