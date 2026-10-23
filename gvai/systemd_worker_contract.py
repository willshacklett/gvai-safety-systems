"""Dormant, deny-only contract. No systemd transport, launch or publication."""

from __future__ import annotations

from dataclasses import dataclass
import threading
from typing import Protocol
from uuid import UUID, uuid4

from gvai.linux_containment_identity import ContainmentIdentity
from gvai.linux_containment_stop import CleanupEvidence
from gvai.supervisor_stop import StopJournal, StopState


REQUIRED_RESTRICTIONS = frozenset({
    "nonroot-unique-identity", "zero-capabilities", "no-new-privileges",
    "enforcing-apparmor", "seccomp-no-spawn", "seccomp-no-sockets",
    "private-network", "private-mount", "private-pid", "private-user",
    "private-uts", "private-ipc", "readonly-root-and-input",
    "bounded-private-scratch", "no-host-sockets-or-control-fds",
    "no-supervisor-manager-or-publication-access", "no-cgroup-migration",
    "contained-before-exec", "supervisor-loss-kills-workers",
})


@dataclass(frozen=True)
class WorkerIdentity:
    attempt: UUID
    boot: UUID
    cgroup: ContainmentIdentity

    def __post_init__(self):
        if (
            type(self.attempt) is not UUID or self.attempt.int == 0
            or type(self.boot) is not UUID or self.boot.int == 0
            or type(self.cgroup) is not ContainmentIdentity
            or type(self.cgroup.device) is not int or self.cgroup.device < 0
            or type(self.cgroup.inode) is not int or self.cgroup.inode <= 0
        ):
            raise ValueError("Exact attempt, boot and dedicated cgroup identity required.")

    @property
    def service(self) -> str:
        return f"gvai-worker-{self.attempt.hex}.service"


@dataclass(frozen=True)
class ResourceLimits:
    memory_bytes: int
    tasks: int
    cpu_quota_percent: int
    scratch_bytes: int

    def __post_init__(self):
        if any(
            type(value) is not int or value <= 0
            for value in (
                self.memory_bytes, self.tasks, self.cpu_quota_percent, self.scratch_bytes,
            )
        ):
            raise ValueError("Explicit positive bounded resource limits required.")


@dataclass(frozen=True)
class WorkerSpec:
    identity: WorkerIdentity
    uid: int
    gid: int
    limits: ResourceLimits

    def __post_init__(self):
        if (
            type(self.identity) is not WorkerIdentity
            or type(self.uid) is not int or self.uid <= 0
            or type(self.gid) is not int or self.gid <= 0
            or type(self.limits) is not ResourceLimits
        ):
            raise ValueError("Fixed non-root worker specification required.")


def _valid_worker_spec(spec: object) -> bool:
    if type(spec) is not WorkerSpec or type(spec.identity) is not WorkerIdentity:
        return False
    identity = spec.identity
    cgroup = identity.cgroup
    limits = spec.limits
    return (
        type(identity.attempt) is UUID and identity.attempt.int != 0
        and type(identity.boot) is UUID and identity.boot.int != 0
        and type(cgroup) is ContainmentIdentity
        and type(cgroup.device) is int and cgroup.device >= 0
        and type(cgroup.inode) is int and cgroup.inode > 0
        and type(spec.uid) is int and spec.uid > 0
        and type(spec.gid) is int and spec.gid > 0
        and type(limits) is ResourceLimits
        and all(type(value) is int and value > 0 for value in (
            limits.memory_bytes, limits.tasks,
            limits.cpu_quota_percent, limits.scratch_bytes,
        ))
    )


@dataclass(frozen=True)
class ManagerObservation:
    session: UUID
    request: UUID
    spec: WorkerSpec
    service: str
    restrictions: frozenset[str]
    reaper: str
    kill_requested: bool
    empty: bool
    descendants_reaped: bool
    terminal: bool


@dataclass(frozen=True)
class ManagerInventory:
    session: UUID
    request: UUID
    boot: UUID
    complete: bool
    workers: tuple[WorkerSpec, ...]


class TrustedManager(Protocol):
    """Trusted adapter only; records do not authenticate their own provenance."""

    def inventory(self, session: UUID, request: UUID) -> ManagerInventory: ...

    def cancel(
        self, spec: WorkerSpec, session: UUID, request: UUID,
    ) -> ManagerObservation: ...


@dataclass(frozen=True)
class BackendReport:
    state: StopState
    durable: bool
    cleanup: CleanupEvidence
    reconciled: bool
    errors: tuple[str, ...]

    @property
    def allowed(self) -> bool:
        return False

    @property
    def authenticated(self) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


@dataclass(frozen=True)
class OutputFence:
    identity: WorkerIdentity
    session: UUID
    revision: int


@dataclass(frozen=True)
class OutputDenial:
    reason: str

    @property
    def allowed(self) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


class SystemdWorkerContract:
    """Single supervisor owner; starts and remains stopped, including restart."""

    def __init__(self, journal: StopJournal, manager: TrustedManager, boot: UUID):
        if type(journal) is not StopJournal or type(boot) is not UUID or boot.int == 0:
            raise ValueError("Protected STOP journal and explicit boot required.")
        self._journal = journal
        self._manager = manager
        self._boot = boot
        self._session = uuid4()
        self._revision = 0
        self._workers: dict[UUID, WorkerSpec] = {}
        self._reconciled = False
        self._lock = threading.Lock()

    def _remember(self, spec: WorkerSpec) -> None:
        if not _valid_worker_spec(spec) or spec.identity.boot != self._boot:
            raise ValueError("Worker specification or boot mismatch.")
        previous = self._workers.get(spec.identity.attempt)
        if previous is not None and previous != spec:
            raise ValueError("Attempt identity cannot be rebound.")
        for other in self._workers.values():
            if other.identity.attempt != spec.identity.attempt and (
                other.identity.cgroup == spec.identity.cgroup or other.uid == spec.uid
            ):
                raise ValueError("Dedicated cgroup and worker UID cannot be shared.")
        self._workers[spec.identity.attempt] = spec

    def register(self, spec: WorkerSpec) -> BackendReport:
        with self._lock:
            self._remember(spec)
            self._reconciled = False
            return self._stop(())

    def request_stop(self) -> BackendReport:
        with self._lock:
            return self._stop(())

    def reconcile(self) -> BackendReport:
        with self._lock:
            self._reconciled = False
            request = uuid4()
            errors = []
            try:
                inventory = self._manager.inventory(self._session, request)
                if (
                    type(inventory) is not ManagerInventory
                    or type(inventory.session) is not UUID or inventory.session != self._session
                    or type(inventory.request) is not UUID or inventory.request != request
                    or type(inventory.boot) is not UUID or inventory.boot != self._boot
                    or inventory.complete is not True
                    or type(inventory.workers) is not tuple
                ):
                    raise ValueError("Incomplete or uncorrelated manager inventory.")
                seen = set()
                for spec in inventory.workers:
                    if type(spec) is not WorkerSpec or spec.identity.attempt in seen:
                        raise ValueError("Invalid or duplicate inventory worker.")
                    seen.add(spec.identity.attempt)
                    self._remember(spec)
                if seen != set(self._workers):
                    raise ValueError("Manager inventory omitted a known attempt.")
            except Exception as error:
                errors.append(f"inventory: {type(error).__name__}: {error}")
            report = self._stop(tuple(errors), allow_empty=not errors)
            self._reconciled = not report.errors and report.cleanup.status == "terminated"
            return BackendReport(
                report.state, report.durable, report.cleanup, self._reconciled, report.errors,
            )

    def _observe(self, spec: WorkerSpec) -> CleanupEvidence:
        from gvai.systemd_observation_validator import validate_observation

        request = uuid4()
        observation = self._manager.cancel(spec, self._session, request)
        validation = validate_observation(observation, spec, self._session, request)
        if not validation.structurally_valid:
            raise ValueError(validation.reason)
        return CleanupEvidence(
            "terminated" if validation.cleanup_complete else "pending",
            observation.kill_requested,
            observation.empty, observation.descendants_reaped,
        )

    def _stop(
        self, initial_errors: tuple[str, ...], *, allow_empty: bool = False,
    ) -> BackendReport:
        self._revision += 1
        errors = list(initial_errors)
        if not self._workers and not allow_empty:
            errors.append("No complete manager inventory or registered containment.")
        evidence = []
        for spec in self._workers.values():
            try:
                evidence.append(self._observe(spec))
            except Exception as error:
                errors.append(f"{spec.identity.service}: {type(error).__name__}: {error}")
        try:
            state, durable = self._journal.latch()
        except Exception as error:
            state, durable = StopState(None, True), False
            errors.append(f"journal: {type(error).__name__}: {error}")
        if not durable or state.uncertain:
            errors.append("STOP journal is not durably certain.")
        complete = not errors and all(item.status == "terminated" for item in evidence)
        cleanup = CleanupEvidence(
            "uncertain" if errors else "terminated" if complete else "pending",
            bool(evidence) and all(item.kill_requested for item in evidence),
            complete, complete,
        )
        if not complete:
            self._reconciled = False
        return BackendReport(state, durable, cleanup, self._reconciled, tuple(errors))

    def output_fence(self, identity: WorkerIdentity) -> OutputFence:
        """Correlation only, never an execution or publication credential."""
        with self._lock:
            if (
                type(identity) is not WorkerIdentity
                or identity.attempt not in self._workers
                or self._workers[identity.attempt].identity != identity
            ):
                raise ValueError("Unknown output attempt.")
            return OutputFence(identity, self._session, self._revision)

    def check_output(self, fence: OutputFence) -> OutputDenial:
        with self._lock:
            if (
                type(fence) is not OutputFence
                or type(fence.identity) is not WorkerIdentity
                or type(fence.session) is not UUID or fence.session != self._session
                or type(fence.revision) is not int or fence.revision != self._revision
                or fence.identity.attempt not in self._workers
                or self._workers[fence.identity.attempt].identity != fence.identity
            ):
                return OutputDenial("Unknown or stale output fence; publication denied.")
            return OutputDenial("STOP is latched; publication is not implemented.")
