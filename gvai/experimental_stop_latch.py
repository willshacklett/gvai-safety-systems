"""Experimental fail-closed STOP latch (in-process verification prototype).

This module verifies signed STOP/ARM commands and decides whether a workload
may proceed. It is NOT an independently enforced shutdown: everything here
runs in the verifier's process, and anyone who controls that process (or the
injected anchor/store objects) controls the answer. See
docs/stop_latch_prototype_v1.md.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Protocol

ENFORCEMENT_MODEL = "in_process_verification_only"
INDEPENDENT_ENFORCEMENT_IMPLEMENTED = False

STATUS_STOPPED = "stopped"
STATUS_ARMED = "armed"
STATUS_FAULT = "fault"

COMMAND_STOP = "stop"
COMMAND_ARM = "arm"

_DOMAIN = b"GVAI-STOP-LATCH-V1\n"
_GENESIS_DIGEST = "0" * 64
_MAX_SEQUENCE = 2**53
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SIG_HEX = re.compile(r"[0-9a-f]{128}\Z")
_FIELDS = frozenset(
    {"version", "latch_id", "sequence", "command_type", "key_id", "signature"}
)
_ROLE_FOR_COMMAND = {COMMAND_STOP: "stop", COMMAND_ARM: "arm"}


class StopLatchConfigError(ValueError):
    pass


@dataclass(frozen=True)
class AnchorHead:
    sequence: int
    digest: str


GENESIS_HEAD = AnchorHead(0, _GENESIS_DIGEST)


class TrustedAnchor(Protocol):
    """Monotonic head held outside the verifier's control.

    compare_and_advance must be atomic and refuse any new head whose sequence
    is not strictly greater than the stored one. The in-memory reference below
    provides none of the independence this protocol requires.
    """

    def read(self) -> AnchorHead: ...

    def compare_and_advance(self, expected: AnchorHead, new: AnchorHead) -> bool: ...


class CommandStore(Protocol):
    """Untrusted persistence for the last accepted signed command."""

    def load(self) -> Optional[Mapping[str, object]]: ...

    def save(self, envelope: Mapping[str, object]) -> None: ...


class InMemoryTrustedAnchor:
    """Reference anchor for tests. Same process as the verifier: not independent."""

    def __init__(self, head: AnchorHead = GENESIS_HEAD) -> None:
        self._head = head
        self._lock = threading.Lock()

    def read(self) -> AnchorHead:
        with self._lock:
            return self._head

    def compare_and_advance(self, expected: AnchorHead, new: AnchorHead) -> bool:
        with self._lock:
            if self._head != expected or new.sequence <= self._head.sequence:
                return False
            self._head = new
            return True


class InMemoryCommandStore:
    def __init__(self) -> None:
        self._envelope: Optional[Mapping[str, object]] = None

    def load(self) -> Optional[Mapping[str, object]]:
        return self._envelope

    def save(self, envelope: Mapping[str, object]) -> None:
        self._envelope = dict(envelope)


@dataclass(frozen=True)
class StopCommand:
    latch_id: str
    sequence: int
    command_type: str
    key_id: str
    signature: bytes

    def signing_bytes(self) -> bytes:
        return signing_bytes(
            self.latch_id, self.sequence, self.command_type, self.key_id
        )

    def digest(self) -> str:
        return hashlib.sha256(self.signing_bytes() + self.signature).hexdigest()


def signing_bytes(
    latch_id: str, sequence: int, command_type: str, key_id: str
) -> bytes:
    body = json.dumps(
        {
            "version": 1,
            "latch_id": latch_id,
            "sequence": sequence,
            "command_type": command_type,
            "key_id": key_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return _DOMAIN + body


def parse_command(envelope: object) -> StopCommand:
    if not isinstance(envelope, Mapping) or set(envelope) != _FIELDS:
        raise ValueError("malformed_envelope")
    if type(envelope["version"]) is not int or envelope["version"] != 1:
        raise ValueError("unsupported_version")
    seq = envelope["sequence"]
    if type(seq) is not int or not 1 <= seq <= _MAX_SEQUENCE:
        raise ValueError("invalid_sequence")
    for name in ("latch_id", "command_type", "key_id", "signature"):
        if type(envelope[name]) is not str:
            raise ValueError("malformed_envelope")
    if envelope["command_type"] not in _ROLE_FOR_COMMAND:
        raise ValueError("unknown_command_type")
    if not _IDENTIFIER.fullmatch(envelope["latch_id"]) or not _IDENTIFIER.fullmatch(
        envelope["key_id"]
    ):
        raise ValueError("invalid_identifier")
    if not _SIG_HEX.fullmatch(envelope["signature"]):
        raise ValueError("invalid_signature_encoding")
    return StopCommand(
        envelope["latch_id"],
        seq,
        envelope["command_type"],
        envelope["key_id"],
        bytes.fromhex(envelope["signature"]),
    )


def command_envelope(command: StopCommand) -> dict:
    return {
        "version": 1,
        "latch_id": command.latch_id,
        "sequence": command.sequence,
        "command_type": command.command_type,
        "key_id": command.key_id,
        "signature": command.signature.hex(),
    }


class StopLatchKeyring:
    """Public verification keys only, split by role.

    Stop keys can only stop; arm keys can only arm. Key IDs and raw key bytes
    may not be shared between roles or with any key in `forbidden_public_keys`
    (e.g. commercial receipt or API signing keys), and domain separation in
    the signed bytes prevents cross-protocol signature reuse.
    """

    def __init__(
        self,
        stop_keys: Mapping[str, bytes],
        arm_keys: Mapping[str, bytes],
        forbidden_public_keys: Iterable[bytes] = (),
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        if not stop_keys or not arm_keys:
            raise StopLatchConfigError("both_roles_required")
        if set(stop_keys) & set(arm_keys):
            raise StopLatchConfigError("key_id_shared_across_roles")
        forbidden = {bytes(k) for k in forbidden_public_keys}
        seen: set[bytes] = set()
        self._keys: dict[str, tuple[str, object]] = {}
        for role, keys in (("stop", stop_keys), ("arm", arm_keys)):
            for key_id, raw in keys.items():
                if not isinstance(key_id, str) or not _IDENTIFIER.fullmatch(key_id):
                    raise StopLatchConfigError("invalid_key_id")
                if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32:
                    raise StopLatchConfigError("invalid_public_key")
                raw = bytes(raw)
                if raw in seen:
                    raise StopLatchConfigError("public_key_shared_across_roles")
                if raw in forbidden:
                    raise StopLatchConfigError("public_key_reused_from_other_purpose")
                seen.add(raw)
                try:
                    pub = Ed25519PublicKey.from_public_bytes(raw)
                except Exception as exc:
                    raise StopLatchConfigError("invalid_public_key") from exc
                self._keys[key_id] = (role, pub)

    def verify(self, command: StopCommand) -> bool:
        entry = self._keys.get(command.key_id)
        if entry is None or entry[0] != _ROLE_FOR_COMMAND[command.command_type]:
            return False
        try:
            entry[1].verify(command.signature, command.signing_bytes())
        except Exception:
            return False
        return True


@dataclass(frozen=True)
class LatchDecision:
    allowed: bool
    status: str
    reason: str


@dataclass(frozen=True)
class CommandResult:
    accepted: bool
    status: str
    reason: str
    gap_detected: bool = False


@dataclass(frozen=True)
class ReconcileResult:
    """Read-only answer about one submitted STOP envelope.

    ``verdict`` is EXACT_APPLIED only when the complete identity of the
    submitted command equals the durable record (anchor and store agree).
    ``answered`` is False when the query itself could not be evaluated. Only
    EXACT_APPLIED means a STOP is recorded; other answered verdicts are not.
    """

    answered: bool
    verdict: str
    status: str
    reason: str
    head_sequence: Optional[int] = None
    head_digest: Optional[str] = None
    submitted_digest: Optional[str] = None


class StopLatch:
    """Fail-closed latch. Starts stopped; only a signed, contiguous ARM opens it.

    * Invalid, forged, wrong-role, wrong-latch, stale or replayed commands are
      rejected without changing state (an unauthenticated sender cannot stop
      the workload, and cannot re-open it).
    * An authentic STOP with sequence above the anchor is always honoured, even
      across a sequence gap (gap is flagged); stopping is the safe direction.
    * ARM requires sequence == anchor + 1 and a non-fault latch.
    * Any disagreement between the anchor and the locally held state (rollback,
      fork, anchor ahead, tampered store) makes the latch FAULT, which is
      sticky and denies everything until re-provisioned out of band.
    """

    def __init__(
        self,
        latch_id: str,
        keyring: StopLatchKeyring,
        anchor: TrustedAnchor,
        store: Optional[CommandStore] = None,
    ) -> None:
        if not isinstance(latch_id, str) or not _IDENTIFIER.fullmatch(latch_id):
            raise StopLatchConfigError("invalid_latch_id")
        self._latch_id = latch_id
        self._keyring = keyring
        self._anchor = anchor
        self._store = store if store is not None else InMemoryCommandStore()
        self._lock = threading.Lock()
        self._head = GENESIS_HEAD
        self._status = STATUS_STOPPED
        self._fault_reason = ""
        self._gap_detected = False
        self._load()

    @property
    def status(self) -> str:
        with self._lock:
            return self._status

    @property
    def head(self) -> AnchorHead:
        with self._lock:
            return self._head

    @property
    def gap_detected(self) -> bool:
        with self._lock:
            return self._gap_detected

    def _fault(self, reason: str) -> None:
        self._status = STATUS_FAULT
        self._fault_reason = self._fault_reason or reason

    def _load(self) -> None:
        try:
            anchor_head = self._anchor.read()
            envelope = self._store.load()
        except Exception:
            self._fault("anchor_or_store_unavailable")
            return
        if envelope is None:
            if anchor_head != GENESIS_HEAD:
                self._fault("store_missing_but_anchor_advanced")
            return
        try:
            command = parse_command(envelope)
        except ValueError:
            self._fault("store_corrupt")
            return
        if command.latch_id != self._latch_id or not self._keyring.verify(command):
            self._fault("store_signature_invalid")
            return
        head = AnchorHead(command.sequence, command.digest())
        if head != anchor_head:
            self._fault(
                "store_rollback_detected"
                if anchor_head.sequence > head.sequence
                else "store_anchor_mismatch"
            )
            return
        self._head = head
        self._status = (
            STATUS_ARMED if command.command_type == COMMAND_ARM else STATUS_STOPPED
        )

    def permit(self) -> LatchDecision:
        """Return whether the workload may proceed. Never raises."""
        with self._lock:
            try:
                if self._status == STATUS_FAULT:
                    return LatchDecision(False, STATUS_FAULT, self._fault_reason)
                if self._status == STATUS_STOPPED:
                    return LatchDecision(False, STATUS_STOPPED, "latched_stop")
                try:
                    anchor_head = self._anchor.read()
                except Exception:
                    return LatchDecision(False, self._status, "anchor_unavailable")
                if not isinstance(anchor_head, AnchorHead):
                    return LatchDecision(False, self._status, "anchor_invalid")
                if anchor_head != self._head:
                    self._fault(
                        "anchor_rollback_detected"
                        if anchor_head.sequence < self._head.sequence
                        else "anchor_diverged"
                    )
                    return LatchDecision(False, STATUS_FAULT, self._fault_reason)
                return LatchDecision(True, STATUS_ARMED, "armed")
            except Exception:
                return LatchDecision(False, STATUS_FAULT, "internal_error")

    def _durable_record_matches(self, command: StopCommand, head: AnchorHead) -> bool:
        """True only if the anchor and the stored, re-verified command both equal ``command``."""
        try:
            if self._anchor.read() != head:
                return False
            stored = parse_command(self._store.load())
        except Exception:
            return False
        return (
            stored.latch_id == self._latch_id
            and self._keyring.verify(stored)
            and stored.digest() == command.digest()
            and AnchorHead(stored.sequence, stored.digest()) == head
        )

    def reconcile(self, envelope: object) -> ReconcileResult:
        """Read-only: relate a submitted signed STOP to the durable record. Never raises.

        Requires a parseable, correctly signed STOP for this latch, so it is
        never an unauthenticated oracle. It changes no state.
        """
        try:
            return self._reconcile(envelope)
        except Exception:
            return ReconcileResult(False, "UNVERIFIABLE", self.status, "internal_error")

    def _reconcile(self, envelope: object) -> ReconcileResult:
        # Authenticate first; nothing about the latch is revealed before that.
        try:
            command = parse_command(envelope)
        except ValueError as exc:
            return ReconcileResult(False, "REJECTED", "", str(exc))
        if not self._keyring.verify(command):
            return ReconcileResult(False, "REJECTED", "", "authentication_failed")
        if command.latch_id != self._latch_id:
            return ReconcileResult(False, "REJECTED", "", "wrong_latch")
        if command.command_type != COMMAND_STOP:
            return ReconcileResult(False, "REJECTED", "", "not_a_stop_command")
        submitted = command.digest()
        with self._lock:
            status = self._status
            try:
                head = self._anchor.read()
                envelope_now = self._store.load()
            except Exception:
                return ReconcileResult(
                    False, "UNVERIFIABLE", status, "anchor_or_store_unavailable",
                    submitted_digest=submitted,
                )
            if envelope_now is None:
                durable_ok = head == GENESIS_HEAD
            else:
                try:
                    stored = parse_command(envelope_now)
                    durable_ok = (
                        stored.latch_id == self._latch_id
                        and self._keyring.verify(stored)
                        and AnchorHead(stored.sequence, stored.digest()) == head
                    )
                except Exception:
                    durable_ok = False
            reason = None
            if status == STATUS_FAULT:
                reason = self._fault_reason or "latch_fault"
            elif not durable_ok:
                reason = "durable_record_inconsistent"
            elif head != self._head:
                # The files no longer match what this live latch applied (rollback or substitution).
                reason = (
                    "anchor_rollback_detected"
                    if head.sequence < self._head.sequence
                    else "anchor_diverged"
                )
            if reason is not None:
                return ReconcileResult(
                    False, "UNVERIFIABLE", status, reason, head.sequence, head.digest, submitted
                )
            if command.sequence > head.sequence:
                verdict = "NOT_APPLIED"
            elif command.sequence == head.sequence:
                verdict = "EXACT_APPLIED" if submitted == head.digest else "CONFLICT"
            else:
                verdict = "SUPERSEDED_UNVERIFIED"
            if verdict == "EXACT_APPLIED" and status != STATUS_STOPPED:
                return ReconcileResult(
                    False, "UNVERIFIABLE", status, "live_status_not_stopped",
                    head.sequence, head.digest, submitted,
                )
            return ReconcileResult(
                True, verdict, status, verdict.lower(), head.sequence, head.digest, submitted
            )

    def apply(self, envelope: object) -> CommandResult:
        """Verify and apply a signed command. Never raises."""
        try:
            return self._apply(envelope)
        except Exception:
            return CommandResult(False, self.status, "internal_error")

    def _apply(self, envelope: object) -> CommandResult:
        try:
            command = parse_command(envelope)
        except ValueError as exc:
            return CommandResult(False, self.status, str(exc))
        if command.latch_id != self._latch_id:
            return CommandResult(False, self.status, "wrong_latch")
        if not self._keyring.verify(command):
            return CommandResult(False, self.status, "authentication_failed")

        with self._lock:
            if self._status == STATUS_FAULT:
                return CommandResult(False, STATUS_FAULT, self._fault_reason)
            try:
                current = self._anchor.read()
            except Exception:
                return CommandResult(False, self._status, "anchor_unavailable")
            if current != self._head:
                self._fault(
                    "anchor_rollback_detected"
                    if current.sequence < self._head.sequence
                    else "anchor_diverged"
                )
                return CommandResult(False, STATUS_FAULT, self._fault_reason)
            if command.sequence <= current.sequence:
                if (
                    command.command_type == COMMAND_STOP
                    and command.sequence == current.sequence
                ):
                    if command.digest() == current.digest:
                        if self._durable_record_matches(command, current):
                            return CommandResult(False, self._status, "already_applied")
                        return CommandResult(False, self._status, "stale_or_replayed")
                    return CommandResult(False, self._status, "conflicting_command")
                return CommandResult(False, self._status, "stale_or_replayed")

            gap = command.sequence != current.sequence + 1
            if command.command_type == COMMAND_ARM and gap:
                return CommandResult(False, self._status, "sequence_gap")

            new_head = AnchorHead(command.sequence, command.digest())
            try:
                advanced = self._anchor.compare_and_advance(current, new_head)
            except Exception:
                advanced = False
            if not advanced:
                if command.command_type == COMMAND_STOP:
                    # Cannot record it, but the safe direction is still taken.
                    self._status = STATUS_STOPPED
                    self._fault("anchor_advance_failed")
                    return CommandResult(False, STATUS_FAULT, "anchor_advance_failed")
                return CommandResult(False, self._status, "anchor_advance_failed")

            self._head = new_head
            if command.command_type == COMMAND_STOP:
                self._status = STATUS_STOPPED
                self._gap_detected = self._gap_detected or gap
            else:
                self._status = STATUS_ARMED
            try:
                self._store.save(command_envelope(command))
            except Exception:
                self._status = STATUS_STOPPED
                self._fault("store_write_failed")
                return CommandResult(False, STATUS_FAULT, "store_write_failed", gap)
            return CommandResult(True, self._status, "accepted", gap)
