"""Dormant request boundary for a future authenticated systemd manager."""

from __future__ import annotations

from dataclasses import dataclass
import threading
from typing import Literal, Optional, Protocol
from uuid import UUID

from gvai.systemd_observation_validator import validate_observation
from gvai.systemd_worker_contract import (
    ManagerInventory,
    ManagerObservation,
    WorkerSpec,
    _valid_worker_spec,
)

MANAGER_REQUEST_TIMEOUT_SECONDS = 1.0
MAX_MANAGER_REQUEST_BYTES = 4096
MAX_MANAGER_RESPONSE_BYTES = 1_048_576
MAX_INVENTORY_WORKERS = 256
MAX_TRACKED_REQUESTS = 65_536
MAX_SPEC_INTEGER = (1 << 64) - 1
WORKER_SERVICE_PREFIX = "gvai-worker-"


def _bounded_worker_spec(spec: object) -> bool:
    if not _valid_worker_spec(spec):
        return False
    return all(value <= MAX_SPEC_INTEGER for value in (
        spec.identity.cgroup.device,
        spec.identity.cgroup.inode,
        spec.uid,
        spec.gid,
        spec.limits.memory_bytes,
        spec.limits.tasks,
        spec.limits.cpu_quota_percent,
        spec.limits.scratch_bytes,
    ))


class ManagerBoundaryError(RuntimeError):
    """A request could not be authenticated and structurally validated."""


@dataclass(frozen=True)
class ManagerRequest:
    operation: Literal["inventory", "cancel"]
    boot: UUID
    session: UUID
    request: UUID
    service_scope: Optional[str] = None
    spec: Optional[WorkerSpec] = None

    def __post_init__(self):
        if (
            type(self.operation) is not str
            or self.operation not in ("inventory", "cancel")
            or type(self.boot) is not UUID or self.boot.int == 0
            or type(self.session) is not UUID or self.session.int == 0
            or type(self.request) is not UUID or self.request.int == 0
        ):
            raise ValueError("Invalid manager request operation or correlation.")
        if self.operation == "inventory":
            if self.service_scope != WORKER_SERVICE_PREFIX or self.spec is not None:
                raise ValueError("Inventory requests are limited to the fixed worker namespace.")
        elif (
            not _bounded_worker_spec(self.spec)
            or self.spec.identity.boot != self.boot
            or type(self.service_scope) is not str
            or self.service_scope != self.spec.identity.service
        ):
            raise ValueError("Cancel requests require a fixed worker identity.")


@dataclass(frozen=True)
class ManagerTransportReply:
    response: object
    peer_evidence: object


class ManagerTransport(Protocol):
    """The concrete transport must enforce the supplied time and byte limits."""

    def exchange(
        self,
        request: ManagerRequest,
        timeout_seconds: float,
        max_request_bytes: int,
        max_response_bytes: int,
    ) -> ManagerTransportReply: ...


class ManagerAuthenticator(Protocol):
    """Verifies external peer evidence for this exact request and response."""

    def verify(
        self,
        request: ManagerRequest,
        response: object,
        peer_evidence: object,
    ) -> bool: ...


class SystemdManagerBoundary:
    """TrustedManager-compatible adapter; no transport or auth is provided here."""

    def __init__(
        self, boot: UUID, transport: ManagerTransport, authenticator: ManagerAuthenticator,
    ):
        if type(boot) is not UUID or boot.int == 0:
            raise ValueError("Explicit nonzero host boot identity required.")
        if transport is None or authenticator is None:
            raise ValueError("Manager transport and external authenticator are mandatory.")
        self._boot = boot
        self._transport = transport
        self._authenticator = authenticator
        self._request_lock = threading.Lock()
        self._consumed_requests: dict[UUID, set[UUID]] = {}
        self._tracked_request_count = 0

    def inventory(self, session: UUID, request: UUID) -> ManagerInventory:
        envelope = ManagerRequest(
            "inventory", self._boot, session, request, WORKER_SERVICE_PREFIX,
        )
        response = self._exchange(envelope)
        if type(response) is not ManagerInventory:
            raise ManagerBoundaryError("Malformed manager inventory response.")
        if (
            type(response.session) is not UUID
            or type(response.request) is not UUID
            or type(response.boot) is not UUID
            or response.session != envelope.session
            or response.request != envelope.request
            or response.boot != envelope.boot
            or response.complete is not True
            or type(response.workers) is not tuple
            or len(response.workers) > MAX_INVENTORY_WORKERS
        ):
            raise ManagerBoundaryError("Stale, incomplete, or oversized manager inventory.")

        attempts = set()
        cgroups = set()
        uids = set()
        for spec in response.workers:
            if (
                not _bounded_worker_spec(spec)
                or spec.identity.boot != self._boot
                or spec.identity.attempt in attempts
                or spec.identity.cgroup in cgroups
                or spec.uid in uids
            ):
                raise ManagerBoundaryError("Invalid or duplicate worker in manager inventory.")
            attempts.add(spec.identity.attempt)
            cgroups.add(spec.identity.cgroup)
            uids.add(spec.uid)
        return response

    def cancel(
        self, spec: WorkerSpec, session: UUID, request: UUID,
    ) -> ManagerObservation:
        if not _bounded_worker_spec(spec) or spec.identity.boot != self._boot:
            raise ManagerBoundaryError("Invalid or wrong-boot worker specification.")
        envelope = ManagerRequest(
            "cancel", self._boot, session, request, spec.identity.service, spec,
        )
        response = self._exchange(envelope)
        validation = validate_observation(response, spec, session, request)
        if not validation.structurally_valid:
            raise ManagerBoundaryError(validation.reason)
        return response

    def _exchange(self, request: ManagerRequest) -> object:
        self._consume_request_id(request.session, request.request)
        try:
            reply = self._transport.exchange(
                request, timeout_seconds=MANAGER_REQUEST_TIMEOUT_SECONDS,
                max_request_bytes=MAX_MANAGER_REQUEST_BYTES,
                max_response_bytes=MAX_MANAGER_RESPONSE_BYTES,
            )
        except TimeoutError as error:
            raise ManagerBoundaryError("Manager request timed out.") from error
        except (ConnectionError, OSError) as error:
            raise ManagerBoundaryError("Manager transport disconnected.") from error
        if type(reply) is not ManagerTransportReply or reply.peer_evidence is None:
            raise ManagerBoundaryError("Manager reply lacks external peer evidence.")
        try:
            authenticated = self._authenticator.verify(
                request, reply.response, reply.peer_evidence,
            )
        except Exception as error:
            raise ManagerBoundaryError("External manager authentication failed.") from error
        if authenticated is not True:
            raise ManagerBoundaryError("External manager authentication failed.")
        return reply.response

    def _consume_request_id(self, session: UUID, request: UUID) -> None:
        with self._request_lock:
            session_requests = self._consumed_requests.get(session)
            if session_requests is not None and request in session_requests:
                raise ManagerBoundaryError("Manager request ID was already consumed.")
            if self._tracked_request_count >= MAX_TRACKED_REQUESTS:
                raise ManagerBoundaryError("Manager request tracking capacity exhausted.")
            if session_requests is None:
                session_requests = set()
                self._consumed_requests[session] = session_requests
            session_requests.add(request)
            self._tracked_request_count += 1
