"""Offline evidence exchange model, not an authenticator or runtime verifier."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import secrets
import threading
import time
from typing import Callable, Protocol
from uuid import UUID

from gvai.launcher_worker_contract import (
    EvidenceRequest, EvidenceRequirement, LifecycleState, PROPOSED_WORKER_LABEL,
    required_evidence,
)
from gvai.systemd_worker_profile import REQUIRED_NAMESPACES, WORKER_SECCOMP_POLICY_ID
from gvai.systemd_worker_contract import WorkerSpec, _valid_worker_spec

MAX_CHALLENGE_LIFETIME_NS = 5_000_000_000


def _positive(value: object) -> bool:
    return type(value) is int and value > 0


def _digest(value: object) -> bool:
    return (
        type(value) is str and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True)
class ObjectPin:
    device: int
    inode: int

    def __post_init__(self) -> None:
        if type(self.device) is not int or self.device < 0 or not _positive(self.inode):
            raise ValueError("Exact pinned filesystem identity required.")


@dataclass(frozen=True)
class ArtifactIdentity:
    pin: ObjectPin
    sha256: str

    def __post_init__(self) -> None:
        if type(self.pin) is not ObjectPin or not _digest(self.sha256):
            raise ValueError("Pinned artifact and exact SHA-256 required.")


@dataclass(frozen=True)
class ProcessLifetime:
    """Expected independently held lifetime pin; numbers alone do not prove it."""

    pid: int
    start_ticks: int
    pid_namespace: ObjectPin
    handle_binding: bytes

    def __post_init__(self) -> None:
        if (
            not _positive(self.pid) or not _positive(self.start_ticks)
            or type(self.pid_namespace) is not ObjectPin
            or type(self.handle_binding) is not bytes or len(self.handle_binding) != 32
        ):
            raise ValueError("Process lifetime and independent handle binding required.")


@dataclass(frozen=True)
class EntryIdentity:
    boot: UUID
    attempt: UUID
    service: str
    process: ProcessLifetime
    cgroup: ObjectPin
    launcher: ArtifactIdentity

    def __post_init__(self) -> None:
        if (
            type(self.boot) is not UUID or self.boot.int == 0
            or type(self.attempt) is not UUID or self.attempt.int == 0
            or type(self.service) is not str
            or self.service != f"gvai-worker-{self.attempt.hex}.service"
            or type(self.process) is not ProcessLifetime
            or type(self.cgroup) is not ObjectPin
            or type(self.launcher) is not ArtifactIdentity
        ):
            raise ValueError("Exact boot, attempt, fixed service and pinned entry identity required.")


@dataclass(frozen=True)
class VerifierIdentity:
    artifact: ArtifactIdentity
    trust_anchor_sha256: str

    def __post_init__(self) -> None:
        if type(self.artifact) is not ArtifactIdentity or not _digest(self.trust_anchor_sha256):
            raise ValueError("Externally provisioned verifier identity required.")


class MappingStage(Enum):
    INITIAL = "initial"
    FINAL = "final"


@dataclass(frozen=True)
class MappingEvidence:
    stage: MappingStage
    procfs: ObjectPin
    connected_to_current_namespace: bool
    uid_map: tuple[tuple[int, int, int], ...]
    gid_map: tuple[tuple[int, int, int], ...]
    setgroups_sequence_verified: bool


@dataclass(frozen=True)
class MappingPlan:
    """Supervisor-selected mapping intent, never copied from a worker reply."""

    stage: MappingStage
    uid_map: tuple[tuple[int, int, int], ...]
    gid_map: tuple[tuple[int, int, int], ...]


class ObservationState(Enum):
    OBSERVED = "observed"
    UNVERIFIED = "unverified"
    FAILED = "failed"


@dataclass(frozen=True)
class EntryObservation:
    requirement: EvidenceRequirement
    process: ProcessLifetime
    observed_at_ns: int
    state: ObservationState
    provenance_sha256: str


@dataclass(frozen=True)
class EntryChallenge:
    request: EvidenceRequest
    identity: EntryIdentity
    verifier: VerifierIdentity
    nonce: bytes
    epoch: int
    issued_at_ns: int
    expires_at_ns: int
    mapping_plan: tuple[MappingPlan, ...]

    def __post_init__(self) -> None:
        if (
            type(self.identity) is not EntryIdentity
            or type(self.verifier) is not VerifierIdentity
            or not _valid_request(self.request, self.identity)
            or type(self.nonce) is not bytes or len(self.nonce) != 32
            or not _positive(self.epoch)
            or type(self.issued_at_ns) is not int or self.issued_at_ns < 0
            or type(self.expires_at_ns) is not int or self.expires_at_ns <= self.issued_at_ns
            or not _valid_mapping_plan(self.mapping_plan)
        ):
            raise ValueError("Exact request, identity, nonce, epoch, lifetime and mapping plan required.")


@dataclass(frozen=True)
class EntryResponse:
    challenge: EntryChallenge
    identity: EntryIdentity
    verifier: VerifierIdentity
    observed_at_ns: int
    observations: tuple[EntryObservation, ...]
    namespaces: tuple[tuple[str, ObjectPin], ...]
    mappings: tuple[MappingEvidence, ...]
    apparmor_label: str
    seccomp_policy_id: str
    authentication: bytes


class EntryAuthenticator(Protocol):
    """External TCB seam, not implemented here.

    Must authenticate the entire immutable response and challenge against the
    independently provisioned verifier, not echo self-reported identity fields.
    """

    def authenticate(self, challenge: EntryChallenge, response: EntryResponse) -> bool: ...


@dataclass(frozen=True)
class EntryReport:
    consistent: bool
    stop_requested: bool
    errors: tuple[str, ...]

    @property
    def authenticated(self) -> bool:
        return False

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


def _valid_request(request: object, identity: EntryIdentity) -> bool:
    if (
        type(request) is not EvidenceRequest
        or type(request.session) is not UUID or request.session.int == 0
        or type(request.revision) is not int or request.revision < 0
        or request.previous is not LifecycleState.INPUT_AND_SECCOMP_VERIFIED
        or request.target is not LifecycleState.WORKER_CONFINEMENT_VERIFIED
    ):
        return False
    return type(request.spec) is WorkerSpec and _valid_worker_spec(request.spec) and (
        request.spec.identity.boot == identity.boot
        and request.spec.identity.attempt == identity.attempt
        and request.spec.identity.service == identity.service
        and request.spec.identity.cgroup.device == identity.cgroup.device
        and request.spec.identity.cgroup.inode == identity.cgroup.inode
    )


def _valid_map(value: object) -> bool:
    return (
        type(value) is tuple and bool(value)
        and all(
            type(row) is tuple and len(row) == 3
            and all(type(item) is int and item >= 0 for item in row)
            and row[2] > 0 for row in value
        )
    )


def _valid_mapping_plan(value: object) -> bool:
    return (
        type(value) is tuple and len(value) == 2
        and all(
            type(item) is MappingPlan and type(item.stage) is MappingStage
            and _valid_map(item.uid_map) and _valid_map(item.gid_map) for item in value
        )
        and {item.stage for item in value} == set(MappingStage)
    )


def _response_failure(
    challenge: EntryChallenge, response: object, now_ns: int,
) -> str | None:
    if type(response) is not EntryResponse:
        return "Malformed entry response."
    if (
        type(response.challenge) is not EntryChallenge
        or response.challenge != challenge
        or type(response.identity) is not EntryIdentity or response.identity != challenge.identity
        or type(response.verifier) is not VerifierIdentity or response.verifier != challenge.verifier
    ):
        return "Response correlation, process lifetime or verifier identity mismatch."
    if (
        type(response.observed_at_ns) is not int
        or not challenge.issued_at_ns <= response.observed_at_ns <= now_ns < challenge.expires_at_ns
    ):
        return "Stale, future or expired evidence."
    if (
        type(response.observations) is not tuple
        or len(response.observations) != len(required_evidence(challenge.request.target))
    ):
        return "Incomplete entry evidence."
    seen = set()
    for observation in response.observations:
        if (
            type(observation) is not EntryObservation
            or type(observation.requirement) is not EvidenceRequirement
            or observation.requirement in seen
            or type(observation.process) is not ProcessLifetime
            or observation.process != challenge.identity.process
            or observation.state is not ObservationState.OBSERVED
            or type(observation.observed_at_ns) is not int
            or not challenge.issued_at_ns <= observation.observed_at_ns <= response.observed_at_ns
            or not _digest(observation.provenance_sha256)
        ):
            return "Ambiguous, stale, failed or incorrectly bound observation."
        seen.add(observation.requirement)
    if seen != required_evidence(challenge.request.target):
        return "Missing required entry observation."
    if (
        type(response.namespaces) is not tuple or len(response.namespaces) != len(REQUIRED_NAMESPACES)
        or any(
            type(item) is not tuple or len(item) != 2
            or type(item[0]) is not str or type(item[1]) is not ObjectPin
            for item in response.namespaces
        )
        or {item[0] for item in response.namespaces} != REQUIRED_NAMESPACES
        or dict(response.namespaces)["pid"] != challenge.identity.process.pid_namespace
    ):
        return "Incomplete or mismatched namespace identities."
    if type(response.mappings) is not tuple or len(response.mappings) != 2:
        return "Both connected-procfs mapping stages are required."
    stages = set()
    mapping_plan = {item.stage: item for item in challenge.mapping_plan}
    for mapping in response.mappings:
        if (
            type(mapping) is not MappingEvidence or type(mapping.stage) is not MappingStage
            or mapping.stage in stages or type(mapping.procfs) is not ObjectPin
            or mapping.connected_to_current_namespace is not True
            or mapping.setgroups_sequence_verified is not True
            or not _valid_map(mapping.uid_map) or not _valid_map(mapping.gid_map)
            or mapping.uid_map != mapping_plan[mapping.stage].uid_map
            or mapping.gid_map != mapping_plan[mapping.stage].gid_map
        ):
            return "Unverified connected procfs, UID/GID maps or setgroups sequence."
        stages.add(mapping.stage)
    if (
        type(response.apparmor_label) is not str or response.apparmor_label != PROPOSED_WORKER_LABEL
        or type(response.seccomp_policy_id) is not str
        or response.seccomp_policy_id != WORKER_SECCOMP_POLICY_ID
        or type(response.authentication) is not bytes or not response.authentication
    ):
        return "Wrong confinement, seccomp identity or absent authentication."
    return None


class TrustedEntryExchange:
    """Single supervisor-owned exchange; all success-shaped results remain inert."""

    def __init__(
        self, identity: EntryIdentity, verifier: VerifierIdentity,
        mapping_plan: tuple[MappingPlan, ...],
        approved_request: EvidenceRequest,
        authenticator: EntryAuthenticator | None = None, *, lifetime_ns: int = 1_000_000_000,
        clock: Callable[[], int] = time.monotonic_ns,
    ):
        if (
            type(identity) is not EntryIdentity or type(verifier) is not VerifierIdentity
            or not _positive(lifetime_ns) or lifetime_ns > MAX_CHALLENGE_LIFETIME_NS
            or not _valid_mapping_plan(mapping_plan)
            or not _valid_request(approved_request, identity)
        ):
            raise ValueError("Pinned entry, verifier, approved request, mapping plan and bounded lifetime required.")
        self._identity = identity
        self._verifier = verifier
        self._mapping_plan = mapping_plan
        self._approved_request = approved_request
        self._authenticator = authenticator
        self._lifetime_ns = lifetime_ns
        self._clock = clock
        self._epoch = 0
        self._pending: EntryChallenge | None = None
        self._stopped = False
        self._last_request: EvidenceRequest | None = None
        self._last_issued_at_ns = 0
        self._lock = threading.Lock()

    def issue(self, request: EvidenceRequest) -> EntryChallenge:
        now_ns = self._clock()
        if (
            type(now_ns) is not int or now_ns < 0
            or not _valid_request(request, self._identity)
            or request != self._approved_request
        ):
            raise ValueError("Exact independently approved worker-entry request and trusted monotonic time required.")
        nonce = secrets.token_bytes(32)
        with self._lock:
            if self._stopped:
                raise ValueError("STOP is latched; new entry challenges are forbidden.")
            if (
                request != self._approved_request
                or now_ns < self._last_issued_at_ns
            ):
                raise ValueError("Approved session, specification, revision or monotonic time changed.")
            self._epoch += 1
            challenge = EntryChallenge(
                request, self._identity, self._verifier, nonce, self._epoch,
                now_ns, now_ns + self._lifetime_ns, self._mapping_plan,
            )
            self._pending = challenge
            self._last_issued_at_ns = now_ns
            return challenge

    def request_stop(self) -> EntryReport:
        """Invalidate evidence only; external supervisor still owns actual STOP."""
        with self._lock:
            self._stopped = True
            self._epoch += 1
            self._pending = None
            return EntryReport(False, True, ("STOP latched; entry evidence invalidated.",))

    def assess(
        self, challenge: EntryChallenge, response: object,
    ) -> EntryReport:
        with self._lock:
            if self._stopped or challenge is not self._pending or self._pending is None:
                return EntryReport(False, self._stopped, ("Unknown, consumed or invalidated challenge.",))
            epoch = self._epoch
            self._pending = None

        # Authentication and all external object interpretation remain outside the mutex.
        failure = "Evidence assessment did not complete."
        try:
            now_ns = self._clock()
            if type(now_ns) is not int or now_ns < challenge.issued_at_ns:
                failure = "Invalid or reversed monotonic time."
            else:
                failure = _response_failure(challenge, response, now_ns)
            if failure is None:
                if type(response) is not EntryResponse:
                    failure = "Malformed entry response."
                elif self._authenticator is None:
                    failure = "No independent production authenticator exists."
                elif self._authenticator.authenticate(challenge, response) is not True:
                    failure = "Independent response authentication rejected."
            completed_at_ns = self._clock()
            if (
                type(completed_at_ns) is not int or type(now_ns) is not int
                or completed_at_ns < now_ns
                or completed_at_ns >= challenge.expires_at_ns
            ):
                failure = "Evidence expired or clock reversed during authentication."
        except (OSError, ValueError, TypeError, RuntimeError) as error:
            failure = f"Evidence authentication failed: {type(error).__name__}: {error}"

        with self._lock:
            if self._stopped or epoch != self._epoch:
                return EntryReport(False, self._stopped, ("STOP or newer challenge invalidated reply.",))
            return EntryReport(failure is None, False, () if failure is None else (failure,))
