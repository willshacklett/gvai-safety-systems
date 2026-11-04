"""Disconnected STOP-epoch contract; local durability is optional evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from threading import Lock
from typing import Protocol

from gvai.experimental_stop_latch import (
    COMMAND_STOP, StopCommand, StopLatchKeyring, command_envelope, parse_command,
)

MAX_INTEGER = 2**53
MAX_STOP_EPOCH = MAX_INTEGER
MAX_WRITER_FENCE = MAX_INTEGER
MAX_EVENTS = 256
GENESIS_DIGEST = "0" * 64
EVENT_DOMAIN = b"GVAI-STOP-AUTHORITY-EVENT-V1\n"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _integer(value: object) -> bool:
    return type(value) is int and 0 <= value <= MAX_INTEGER


@dataclass(frozen=True)
class AuthorityEvent:
    authority_id: str
    latch_id: str
    revision: int
    stop_epoch: int
    terminal: bool
    writer_id: str
    writer_fence: int
    kind: str
    command_id: str | None
    command: StopCommand | None
    previous_digest: str
    event_digest: str

    def __post_init__(self) -> None:
        if not all(_identifier(value) for value in (
            self.authority_id, self.latch_id, self.writer_id,
        )):
            raise ValueError("invalid_identity")
        if not all(_integer(value) for value in (
            self.revision, self.stop_epoch, self.writer_fence,
        )) or self.revision == 0 or self.writer_fence == 0:
            raise ValueError("invalid_counter")
        if type(self.terminal) is not bool or self.kind not in ("fence", "stop"):
            raise ValueError("invalid_event")
        for digest in (self.previous_digest, self.event_digest):
            if type(digest) is not str or _HASH.fullmatch(digest) is None:
                raise ValueError("invalid_digest")
        if self.kind == "fence":
            if self.command_id is not None or self.command is not None:
                raise ValueError("invalid_fence_event")
        elif type(self.command_id) is not str or type(self.command) is not StopCommand:
            raise ValueError("invalid_stop_event")


def _event_digest(event: AuthorityEvent) -> str:
    body = {
        "authority_id": event.authority_id, "latch_id": event.latch_id,
        "revision": event.revision, "stop_epoch": event.stop_epoch,
        "terminal": event.terminal, "writer_id": event.writer_id,
        "writer_fence": event.writer_fence, "kind": event.kind,
        "command_id": event.command_id,
        "command": command_envelope(event.command) if event.command is not None else None,
        "previous_digest": event.previous_digest,
    }
    raw = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(EVENT_DOMAIN + raw).hexdigest()


@dataclass(frozen=True)
class AuthoritySnapshot:
    """Full bounded history; no implicit compaction or reset to genesis."""

    authority_id: str
    latch_id: str
    events: tuple[AuthorityEvent, ...] = ()

    def __post_init__(self) -> None:
        if not _identifier(self.authority_id) or not _identifier(self.latch_id):
            raise ValueError("invalid_identity")
        if type(self.events) is not tuple or len(self.events) > MAX_EVENTS:
            raise ValueError("invalid_history")
        if any(type(event) is not AuthorityEvent for event in self.events):
            raise ValueError("invalid_history")

    @property
    def revision(self) -> int:
        return len(self.events)

    @property
    def stop_epoch(self) -> int:
        return self.events[-1].stop_epoch if self.events else 0

    @property
    def terminal(self) -> bool:
        return self.events[-1].terminal if self.events else False

    @property
    def writer_fence(self) -> int:
        return self.events[-1].writer_fence if self.events else 0

    @property
    def writer_id(self) -> str | None:
        return self.events[-1].writer_id if self.events else None

    @property
    def head_digest(self) -> str:
        return self.events[-1].event_digest if self.events else GENESIS_DIGEST


class AuthorityPersistence(Protocol):
    """Future independently owned persistence.

    load must be a linearizable read, not a cached snapshot. Conditional update
    compares the complete expected head/history and atomically stores one event.
    APPLIED means recorded by this adapter, NOT necessarily durable. UNKNOWN
    and exceptions do not prove absence. A durable implementation must specify
    crash barriers and retain exact command history and fencing.
    """

    def load(self) -> AuthoritySnapshot: ...

    def compare_and_swap(
        self, expected: AuthoritySnapshot, proposed: AuthoritySnapshot,
    ) -> str: ...


class LocallyDurableAuthorityPersistence(AuthorityPersistence, Protocol):
    """Optional exact-head local evidence, not independent rollback resistance.

    True is historical evidence that this exact validated snapshot completed
    local synchronization. It is not proof that storage is currently unchanged;
    stale/mismatched heads and invalidated evidence must not receive True.
    Exceptions or invalid results must not become durable acknowledgements.
    """

    def locally_durable(self, snapshot: AuthoritySnapshot) -> bool: ...


def validate_authority_snapshot(
    snapshot: AuthoritySnapshot, authority_id: str, latch_id: str,
    keys: StopLatchKeyring, *, seen: tuple[AuthorityEvent, ...] = (),
) -> None:
    if type(snapshot) is not AuthoritySnapshot:
        raise ValueError("corrupt_history")
    snapshot = AuthoritySnapshot(snapshot.authority_id, snapshot.latch_id, snapshot.events)
    if (snapshot.authority_id, snapshot.latch_id) != (authority_id, latch_id):
        raise ValueError("authority_identity_mismatch")
    epoch, fence, terminal, writer, digest = 0, 0, False, None, GENESIS_DIGEST
    commands: set[str] = set()
    for revision, event in enumerate(snapshot.events, 1):
        AuthorityEvent(**vars(event))
        if (
            (event.authority_id, event.latch_id) != (authority_id, latch_id)
            or event.revision != revision or event.previous_digest != digest
            or event.event_digest != _event_digest(event)
        ):
            raise ValueError("corrupt_history")
        if event.kind == "fence":
            if (
                event.writer_fence != fence + 1 or event.stop_epoch != epoch
                or event.terminal != terminal
            ):
                raise ValueError("inconsistent_revision")
            writer, fence = event.writer_id, event.writer_fence
        else:
            command = parse_command(command_envelope(event.command))
            identity = f"{command.key_id}:{command.sequence}"
            if (
                command.command_type != COMMAND_STOP
                or command.latch_id != latch_id or not keys.verify(command)
                or event.command_id != identity or identity in commands
                or event.writer_id != writer or event.writer_fence != fence
                or event.stop_epoch != epoch + 1 or not event.terminal
            ):
                raise ValueError("inconsistent_stop_history")
            epoch, terminal = event.stop_epoch, True
            commands.add(identity)
        digest = event.event_digest
    if snapshot.events[:len(seen)] != seen:
        raise ValueError("history_rollback_or_fork")


class IndependentCheckpointVerifier(Protocol):
    """Future rollback-resistant, independent head verification.

    True must attest history against the current independent checkpoint, not a
    caller-supplied/local copy. Stage C3 must advance that checkpoint before
    claiming independent rollback-resistant commitment. Local durability alone
    does not make that claim. This interface does not implement advancement.
    """

    def verify(self, snapshot: AuthoritySnapshot) -> bool: ...


class InMemoryAuthorityAdapter:
    """Atomic volatile reference only; never durable or independently trusted."""

    def __init__(self, initial: AuthoritySnapshot) -> None:
        self._snapshot = initial
        self._lock = Lock()

    def load(self) -> AuthoritySnapshot:
        with self._lock:
            return self._snapshot

    def compare_and_swap(
        self, expected: AuthoritySnapshot, proposed: AuthoritySnapshot,
    ) -> str:
        with self._lock:
            if self._snapshot != expected:
                return "CONFLICT"
            if (
                proposed.authority_id != expected.authority_id
                or proposed.latch_id != expected.latch_id
                or proposed.events[:-1] != expected.events
                or len(proposed.events) != len(expected.events) + 1
            ):
                raise ValueError("invalid_conditional_update")
            self._snapshot = proposed
            return "APPLIED"


@dataclass(frozen=True)
class AuthorityOutcome:
    """Evidence, not permission. Durable means local persistence evidence only."""

    reason: str
    requested: bool = False
    recorded: bool = False
    stop_epoch: int | None = None
    revision: int | None = None
    writer_fence: int | None = None
    durable: bool = False
    backend_notified: bool = False
    workload_terminated: bool = False
    deny_execution: bool = True


class StopGenerationAuthority:
    """Trusted supervisor surface, never called by the live latch/gate.

    Fence rotation is a trusted administrative operation, not a workload API.
    Writer tokens fence old sessions but do not authenticate their holders.
    STOP identity is derived from signed V1 key_id/sequence; the sequence is
    not reinterpreted as an epoch and V1 signing bytes remain unchanged.
    """

    def __init__(
        self, authority_id: str, latch_id: str, keys: StopLatchKeyring,
        persistence: AuthorityPersistence,
        checkpoint: IndependentCheckpointVerifier | None = None,
    ) -> None:
        if not _identifier(authority_id) or not _identifier(latch_id):
            raise ValueError("invalid_identity")
        self._authority_id = authority_id
        self._latch_id = latch_id
        self._keys = keys
        self._persistence = persistence
        self._checkpoint = checkpoint
        self._seen: tuple[AuthorityEvent, ...] = ()
        self._fault: str | None = None
        self._lock = Lock()

    def _validate(self, snapshot: AuthoritySnapshot) -> None:
        validate_authority_snapshot(
            snapshot, self._authority_id, self._latch_id, self._keys, seen=self._seen,
        )

    def _load(self) -> AuthoritySnapshot:
        snapshot = self._persistence.load()
        self._validate(snapshot)
        if self._checkpoint is not None:
            if self._checkpoint.verify(snapshot) is not True:
                raise ValueError("checkpoint_unverifiable")
        self._seen = snapshot.events
        return snapshot

    def _result(
        self, reason: str, snapshot: AuthoritySnapshot | None = None,
        *, requested: bool = False, recorded: bool = False,
    ) -> AuthorityOutcome:
        durable = False
        if recorded and snapshot is not None:
            evidence = getattr(self._persistence, "locally_durable", None)
            if evidence is not None:
                durable = evidence(snapshot)
                if type(durable) is not bool:
                    raise ValueError("invalid_durability_evidence")
        return AuthorityOutcome(
            reason, requested, recorded,
            snapshot.stop_epoch if snapshot else None,
            snapshot.revision if snapshot else None,
            snapshot.writer_fence if snapshot else None,
            durable=durable,
        )

    def inspect(self) -> AuthorityOutcome:
        with self._lock:
            if self._fault:
                return self._result(self._fault)
            try:
                return self._result("state_verified", self._load())
            except ValueError:
                self._fault = "authority_state_invalid"
            except Exception:
                self._fault = "authority_unavailable"
            return self._result(self._fault)

    def _append(
        self, snapshot: AuthoritySnapshot, writer: str, fence: int,
        command: StopCommand | None,
    ) -> AuthorityOutcome:
        requested = command is not None
        if len(snapshot.events) >= MAX_EVENTS:
            return self._result("history_exhausted", snapshot, requested=requested)
        epoch = snapshot.stop_epoch + int(requested)
        if epoch > MAX_STOP_EPOCH or fence > MAX_WRITER_FENCE:
            return self._result("epoch_or_fence_exhausted", snapshot, requested=requested)
        if snapshot.revision >= MAX_INTEGER:
            return self._result("revision_exhausted", snapshot, requested=requested)
        event = AuthorityEvent(
            self._authority_id, self._latch_id, snapshot.revision + 1, epoch,
            snapshot.terminal or requested, writer, fence,
            "stop" if requested else "fence",
            f"{command.key_id}:{command.sequence}" if command else None,
            command, snapshot.head_digest, GENESIS_DIGEST,
        )
        event = replace(event, event_digest=_event_digest(event))
        proposed = AuthoritySnapshot(
            self._authority_id, self._latch_id, snapshot.events + (event,),
        )
        self._validate(proposed)
        try:
            result = self._persistence.compare_and_swap(snapshot, proposed)
        except Exception:
            result = "UNKNOWN"
        if result == "APPLIED":
            self._seen = proposed.events
            return self._result(
                "stop_recorded" if requested else "writer_fenced", proposed,
                requested=requested, recorded=requested,
            )
        if result == "CONFLICT":
            return self._result("conditional_conflict", snapshot, requested=requested)
        self._fault = "commit_uncertain"
        return self._result(self._fault, requested=requested)

    def fence_writer(self, writer_id: str, expected_fence: int) -> AuthorityOutcome:
        if not _identifier(writer_id) or not _integer(expected_fence):
            return self._result("invalid_writer")
        with self._lock:
            if self._fault:
                return self._result(self._fault)
            try:
                snapshot = self._load()
                if snapshot.writer_fence != expected_fence:
                    return self._result("stale_writer_fence", snapshot)
                return self._append(snapshot, writer_id, expected_fence + 1, None)
            except ValueError:
                self._fault = "authority_state_invalid"
            except Exception:
                self._fault = "authority_unavailable"
            return self._result(self._fault)

    def request_stop(
        self, envelope: object, *, writer_id: str, writer_fence: int,
    ) -> AuthorityOutcome:
        try:
            command = parse_command(envelope)
        except ValueError:
            return self._result("malformed_stop")
        if (
            command.command_type != COMMAND_STOP or command.latch_id != self._latch_id
            or not self._keys.verify(command)
        ):
            return self._result("authentication_failed")
        if not _identifier(writer_id) or not _integer(writer_fence):
            return self._result("invalid_writer", requested=True)
        with self._lock:
            if self._fault:
                return self._result(self._fault, requested=True)
            try:
                snapshot = self._load()
                if snapshot.writer_id != writer_id:
                    return self._result("conflicting_writer", snapshot, requested=True)
                if writer_fence != snapshot.writer_fence:
                    return self._result("stale_writer_fence", snapshot, requested=True)
                identity = f"{command.key_id}:{command.sequence}"
                for event in snapshot.events:
                    if event.command_id == identity:
                        if event.command != command:
                            return self._result("command_identity_conflict", snapshot, requested=True)
                        return self._result(
                            "already_recorded", snapshot, requested=True, recorded=True,
                        )
                return self._append(snapshot, writer_id, writer_fence, command)
            except ValueError:
                self._fault = "authority_state_invalid"
            except Exception:
                self._fault = "authority_unavailable"
            return self._result(self._fault, requested=True)
