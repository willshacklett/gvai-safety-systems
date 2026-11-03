"""Experimental restart-persistent STOP journal; disconnected, verify-only.

STOP is terminal within an operating generation. This module has no operation
that reverses a STOP and holds no signing authority: a new generation is
recognised only if an offline, separately authenticated OPEN record signed by a
pinned Ed25519 key is already present in the journal. Nothing here creates such
a record, and nothing imports this module. See docs/stop_generation_journal_v1.md.

Local files cannot detect a complete, coherent filesystem rollback. Rollback
and fork detection exist only against an independently held ``JournalAnchor``.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import threading
import time
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


VERSION = 1
GENESIS_HASH = "0" * 64
MAX_RECORDS = 64
MAX_FILE_BYTES = 65536
LOCK_TIMEOUT_SECONDS = 2.0
JOURNAL_NAME = "journal.json"
LOCK_NAME = "journal.lock"
INTENT_NAME = "journal.intent"
PENDING_NAME = "journal.pending"
OPEN_DOMAIN = b"gvai-stop-generation-open-v1\x00"
RECORD_DOMAIN = b"gvai-stop-generation-record-v1\x00"
ROLLBACK_DETECTION_NONE = "none"
ROLLBACK_DETECTION_ANCHOR = "independent_anchor"

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE_HEX = re.compile(r"[0-9a-f]{128}\Z")
_MAX_INT = 2**63 - 1
_OPEN_FIELDS = frozenset({
    "authority_id", "generation", "index", "key_id", "kind", "previous_hash",
    "signature", "trust_domain",
})
_STOP_FIELDS = frozenset({"generation", "index", "kind", "previous_hash", "reason"})


class _Fault(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class _LockTimeout(Exception):
    pass


def _canon(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _int(value: object, low: int, high: int = _MAX_INT) -> bool:
    return type(value) is int and low <= value <= high


@dataclass(frozen=True)
class JournalRecord:
    """One chained journal entry: an offline-signed OPEN or an unsigned STOP.

    STOP records need no secret because stopping is the safe direction; they
    are authenticated only by the hash chain and the filesystem controls.
    """

    kind: str
    generation: int
    index: int
    previous_hash: str
    reason: Optional[str] = None
    authority_id: Optional[str] = None
    trust_domain: Optional[str] = None
    key_id: Optional[str] = None
    signature: Optional[bytes] = None

    def __post_init__(self) -> None:
        if self.kind not in ("open", "stop") or type(self.kind) is not str:
            raise ValueError("Invalid record kind.")
        if not _int(self.generation, 1) or not _int(self.index, 0, MAX_RECORDS - 1):
            raise ValueError("Invalid generation or index.")
        if type(self.previous_hash) is not str or _HASH.fullmatch(self.previous_hash) is None:
            raise ValueError("Invalid previous hash.")
        if self.kind == "stop":
            if not _identifier(self.reason) or any(
                value is not None
                for value in (self.authority_id, self.trust_domain, self.key_id, self.signature)
            ):
                raise ValueError("Invalid STOP record.")
        else:
            if self.reason is not None or not (
                _identifier(self.authority_id)
                and _identifier(self.trust_domain)
                and _identifier(self.key_id)
            ):
                raise ValueError("Invalid OPEN record.")
            if type(self.signature) is not bytes or len(self.signature) != 64:
                raise ValueError("Invalid OPEN signature.")

    def _unsigned_dict(self) -> dict[str, object]:
        record: dict[str, object] = {
            "generation": self.generation,
            "index": self.index,
            "kind": self.kind,
            "previous_hash": self.previous_hash,
        }
        if self.kind == "stop":
            record["reason"] = self.reason
        else:
            record["authority_id"] = self.authority_id
            record["key_id"] = self.key_id
            record["trust_domain"] = self.trust_domain
        return record

    def signing_input(self) -> bytes:
        """Bytes an offline authority signs for an OPEN record (no signing here)."""

        if self.kind != "open":
            raise ValueError("Only OPEN records are signed.")
        return OPEN_DOMAIN + _canon(self._unsigned_dict())

    def to_dict(self) -> dict[str, object]:
        record = self._unsigned_dict()
        if self.kind == "open":
            record["signature"] = self.signature.hex()  # type: ignore[union-attr]
        return record

    def record_hash(self) -> str:
        return hashlib.sha256(RECORD_DOMAIN + _canon(self.to_dict())).hexdigest()


def encode_journal(records: tuple[JournalRecord, ...]) -> bytes:
    return _canon({"records": [record.to_dict() for record in records], "version": VERSION})


def decode_journal(raw: object) -> tuple[JournalRecord, ...]:
    """Strict decoder: exact fields, no duplicates, no coercion, canonical bytes."""

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES:
        raise ValueError("Invalid journal size.")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate field.")
            result[key] = value
        return result

    def reject(_value: str) -> None:
        raise ValueError("Non-finite number.")

    data = json.loads(raw.decode("ascii"), object_pairs_hook=unique, parse_constant=reject)
    if type(data) is not dict or set(data) != {"records", "version"}:
        raise ValueError("Invalid journal fields.")
    if type(data["version"]) is not int or data["version"] != VERSION:
        raise ValueError("Unsupported journal version.")
    items = data["records"]
    if type(items) is not list or not 1 <= len(items) <= MAX_RECORDS:
        raise ValueError("Invalid record count.")
    records = []
    for item in items:
        if type(item) is not dict or type(item.get("kind")) is not str:
            raise ValueError("Invalid record.")
        if item["kind"] == "stop" and set(item) == _STOP_FIELDS:
            records.append(JournalRecord(
                "stop", item["generation"], item["index"], item["previous_hash"],
                reason=item["reason"],
            ))
        elif item["kind"] == "open" and set(item) == _OPEN_FIELDS:
            signature = item["signature"]
            if type(signature) is not str or _SIGNATURE_HEX.fullmatch(signature) is None:
                raise ValueError("Invalid signature encoding.")
            records.append(JournalRecord(
                "open", item["generation"], item["index"], item["previous_hash"],
                authority_id=item["authority_id"], trust_domain=item["trust_domain"],
                key_id=item["key_id"], signature=bytes.fromhex(signature),
            ))
        else:
            raise ValueError("Invalid record fields.")
    result = tuple(records)
    if encode_journal(result) != raw:
        raise ValueError("Noncanonical journal.")
    return result


@dataclass(frozen=True)
class JournalAnchor:
    """Independently held lower bound: the chain must contain this exact head.

    Only an anchor kept outside the journal's storage and administrative
    domain gives rollback or fork detection; it must be advanced by a trusted
    party after each STOP or provisioning step.
    """

    record_count: int
    head_hash: str

    def __post_init__(self) -> None:
        if not _int(self.record_count, 1, MAX_RECORDS):
            raise ValueError("Invalid anchor record count.")
        if type(self.head_hash) is not str or _HASH.fullmatch(self.head_hash) is None:
            raise ValueError("Invalid anchor hash.")


@dataclass(frozen=True)
class JournalState:
    """Informational only. ``stopped=False`` is never an authorization to run."""

    stopped: bool
    generation: Optional[int]
    reason: str
    terminal: bool = False
    fault: bool = False
    record_count: int = 0
    head_hash: str = GENESIS_HASH
    rollback_detection: str = ROLLBACK_DETECTION_NONE


@dataclass(frozen=True)
class StopOutcome:
    """STOP is always in effect in memory; ``durable`` reports only the disk result."""

    stopped: bool
    durable: bool
    reason: str
    state: JournalState


class StopGenerationJournal:
    """Single-directory journal that can record STOP but never reverse it.

    All state is read fresh under a shared lock; once an instance has seen STOP,
    a fault, or a missing journal it reports stopped forever (in-process
    stickiness). Opening a later generation requires a new instance after
    offline provisioning.
    """

    def __init__(
        self,
        directory: str,
        *,
        authority_id: str,
        trust_domain: str,
        trusted_public_keys: Mapping[str, bytes],
        other_purpose_key_ids: frozenset = frozenset(),
        other_purpose_public_keys: frozenset = frozenset(),
        revoked_key_ids: frozenset = frozenset(),
        first_generation: int = 1,
        anchor: Optional[JournalAnchor] = None,
    ) -> None:
        if type(directory) is not str or not directory:
            raise ValueError("A journal directory path is required.")
        if not _identifier(authority_id) or not _identifier(trust_domain):
            raise ValueError("Invalid authority identity.")
        if not _int(first_generation, 1):
            raise ValueError("Invalid first generation.")
        if anchor is not None and type(anchor) is not JournalAnchor:
            raise ValueError("Invalid anchor.")
        if not isinstance(trusted_public_keys, Mapping) or not 0 < len(trusted_public_keys) <= 16:
            raise ValueError("A bounded non-empty pinned key set is required.")
        for ids in (other_purpose_key_ids, revoked_key_ids):
            if type(ids) not in (set, frozenset) or not all(_identifier(i) for i in ids):
                raise ValueError("Invalid key ID set.")
        if type(other_purpose_public_keys) not in (set, frozenset) or any(
            type(k) is not bytes or len(k) != 32 for k in other_purpose_public_keys
        ):
            raise ValueError("Invalid other-purpose public keys.")
        keys: dict[str, Ed25519PublicKey] = {}
        seen: set[bytes] = set()
        for key_id, raw_key in trusted_public_keys.items():
            if not _identifier(key_id) or type(raw_key) is not bytes or len(raw_key) != 32:
                raise ValueError("Invalid pinned public key.")
            if key_id in other_purpose_key_ids or raw_key in other_purpose_public_keys:
                raise ValueError("Provisioning keys must not be reused from another purpose.")
            if raw_key in seen:
                raise ValueError("Duplicate pinned public key.")
            seen.add(raw_key)
            if key_id not in revoked_key_ids:
                keys[key_id] = Ed25519PublicKey.from_public_bytes(raw_key)

        self._authority_id = authority_id
        self._trust_domain = trust_domain
        self._keys = keys
        self._first_generation = first_generation
        self._anchor = anchor
        self._mutex = threading.Lock()
        self._stop_requested = False
        self._poisoned = False
        self._sticky: Optional[JournalState] = None
        self._seen: tuple[str, ...] = ()
        self._dir: Optional[int] = None
        self._lock_fd: Optional[int] = None
        self._lock_id: Optional[tuple[int, int]] = None
        try:
            self._dir = os.open(
                directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            info = os.fstat(self._dir)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise _Fault("unsafe_directory")
            self._lock_fd = os.open(
                LOCK_NAME,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._dir,
            )
            info = os.fstat(self._lock_fd)
            if not self._private_regular(info):
                raise _Fault("unsafe_lock_file")
            self._lock_id = (info.st_dev, info.st_ino)
        except _Fault as fault:
            self._sticky = self._fault_state(fault.code)
        except OSError:
            self._sticky = self._fault_state("journal_unavailable")

    def close(self) -> None:
        """Release descriptors. The instance reports stopped afterwards."""

        with self._mutex:
            self._sticky = self._sticky or self._fault_state("closed")
            for name in ("_lock_fd", "_dir"):
                descriptor = getattr(self, name)
                setattr(self, name, None)
                if descriptor is not None:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass

    @property
    def state(self) -> JournalState:
        with self._mutex:
            return self._observe()

    def latch_stop(self, reason: str = "stop") -> StopOutcome:
        """Record STOP for the current generation. Idempotent; never raises.

        The in-memory STOP takes effect before any storage I/O, so a failed or
        interrupted write can never leave this instance running.
        """

        with self._mutex:
            self._stop_requested = True
            try:
                if not _identifier(reason):
                    reason = "stop"
                return self._latch_stop_locked(reason)
            except Exception:
                self._poisoned = True
                state = self._observe_after_failure("commit_failed")
                return StopOutcome(True, False, "commit_failed", state)

    def _latch_stop_locked(self, reason: str) -> StopOutcome:
        if self._sticky is not None and (self._sticky.fault or self._sticky.terminal):
            return StopOutcome(True, self._sticky.terminal and not self._sticky.fault,
                               self._sticky.reason, self._sticky)
        if self._poisoned or self._dir is None:
            return StopOutcome(True, False, "journal_poisoned", self._observe())
        try:
            with self._flock(exclusive=True):
                state, records = self._evaluate()
                if state.fault or state.terminal or not records:
                    self._sticky = self._sticky or state
                    return StopOutcome(True, state.terminal and not state.fault, state.reason, state)
                tail = records[-1]
                stop = JournalRecord(
                    "stop", tail.generation, len(records), tail.record_hash(), reason=reason
                )
                if len(records) >= MAX_RECORDS:
                    raise _Fault("journal_full")
                updated = records + (stop,)
                try:
                    durable = self._commit(encode_journal(updated))
                except BaseException:
                    self._poisoned = True
                    raise
        except _LockTimeout:
            self._poisoned = True
            return StopOutcome(True, False, "lock_unavailable", self._observe_after_failure("lock_unavailable"))
        except _Fault as fault:
            self._poisoned = True
            return StopOutcome(True, False, fault.code, self._observe_after_failure(fault.code))
        self._seen = tuple(r.record_hash() for r in updated)
        final = self._stopped_state(stop.generation, "stopped", True, updated)
        self._sticky = final
        return StopOutcome(True, durable, "stopped", final)

    def _commit(self, raw: bytes) -> bool:
        """Intent, pending, atomic rename, fsyncs. Crash-left files are never deleted."""

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(INTENT_NAME, flags, 0o600, dir_fd=self._dir)
        try:
            _write_all(fd, b"1")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self._dir)
        fd = os.open(PENDING_NAME, flags, 0o600, dir_fd=self._dir)
        try:
            _write_all(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(PENDING_NAME, JOURNAL_NAME, src_dir_fd=self._dir, dst_dir_fd=self._dir)
        os.fsync(self._dir)
        # The record is now durable; a failed cleanup only leaves conservative evidence.
        try:
            os.unlink(INTENT_NAME, dir_fd=self._dir)
            os.fsync(self._dir)
        except OSError:
            self._poisoned = True
        return True

    def _observe_after_failure(self, code: str) -> JournalState:
        if self._sticky is None:
            self._sticky = self._stopped_state(None, "stop_requested", False, ())
        return self._sticky

    def _observe(self) -> JournalState:
        if self._sticky is not None:
            return self._sticky
        if self._dir is None:
            return self._fault_state("closed")
        try:
            with self._flock(exclusive=False):
                state, _records = self._evaluate()
        except _LockTimeout:
            return self._fault_state("lock_unavailable")
        except _Fault as fault:
            state = self._fault_state(fault.code)
        except Exception:
            state = self._fault_state("internal_error")
        if self._stop_requested and not state.stopped:
            state = self._stopped_state(state.generation, "stop_requested", False, ())
        if state.stopped and state.reason != "lock_unavailable":
            self._sticky = state
        return state

    @contextmanager
    def _flock(self, *, exclusive: bool):
        if self._lock_fd is None or self._dir is None:
            raise _Fault("closed")
        operation = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
        deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
        while True:
            try:
                fcntl.flock(self._lock_fd, operation)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise _LockTimeout() from None
                time.sleep(0.001)
        try:
            try:
                named = os.stat(LOCK_NAME, dir_fd=self._dir, follow_symlinks=False)
            except OSError:
                raise _Fault("lock_substituted") from None
            if (named.st_dev, named.st_ino) != self._lock_id or not self._private_regular(named):
                raise _Fault("lock_substituted")
            yield
        finally:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    @staticmethod
    def _private_regular(info: os.stat_result) -> bool:
        return (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and info.st_uid == os.geteuid()
            and not info.st_mode & 0o077
        )

    def _read_journal(self) -> Optional[bytes]:
        try:
            fd = os.open(
                JOURNAL_NAME,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._dir,
            )
        except FileNotFoundError:
            return None
        except OSError:
            raise _Fault("unsafe_journal_file") from None
        try:
            info = os.fstat(fd)
            if not self._private_regular(info) or info.st_size > MAX_FILE_BYTES:
                raise _Fault("unsafe_journal_file")
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, MAX_FILE_BYTES + 1 - total)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_FILE_BYTES:
                    raise _Fault("unsafe_journal_file")
            return b"".join(chunks)
        finally:
            os.close(fd)

    def _evaluate(self) -> tuple[JournalState, tuple[JournalRecord, ...]]:
        """Caller holds the lock. Never returns an active state on any doubt."""

        try:
            for name in (INTENT_NAME, PENDING_NAME):
                try:
                    os.stat(name, dir_fd=self._dir, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                raise _Fault("incomplete_commit")
            raw = self._read_journal()
            if raw is None:
                if self._seen or self._anchor is not None:
                    raise _Fault("journal_deleted")
                return self._stopped_state(None, "unprovisioned", False, ()), ()
            try:
                records = decode_journal(raw)
            except (ValueError, UnicodeDecodeError):
                raise _Fault("journal_corrupt") from None
            generation, terminal = self._verify_chain(records)
            hashes = tuple(record.record_hash() for record in records)
            self._check_history(hashes)
            self._check_anchor(hashes)
            self._seen = max(self._seen, hashes, key=len)
            if terminal:
                return self._stopped_state(generation, "stopped", True, records), records
            return JournalState(
                False, generation, "not_stopped", False, False, len(records),
                hashes[-1], self._detection(),
            ), records
        except _Fault as fault:
            return self._fault_state(fault.code), ()
        except Exception:
            return self._fault_state("internal_error"), ()

    def _verify_chain(self, records: tuple[JournalRecord, ...]) -> tuple[int, bool]:
        previous_hash = GENESIS_HASH
        for position, record in enumerate(records):
            if record.index != position or record.previous_hash != previous_hash:
                raise _Fault("chain_break")
            before = records[position - 1] if position else None
            if record.kind == "open":
                if before is None:
                    if record.generation != self._first_generation:
                        raise _Fault("unexpected_first_generation")
                elif before.kind != "stop" or record.generation != before.generation + 1:
                    raise _Fault("generation_not_authorised")
                self._verify_open(record)
            elif before is None or before.kind != "open" or before.generation != record.generation:
                raise _Fault("chain_break")
            previous_hash = record.record_hash()
        last = records[-1]
        return last.generation, last.kind == "stop"

    def _verify_open(self, record: JournalRecord) -> None:
        if record.authority_id != self._authority_id or record.trust_domain != self._trust_domain:
            raise _Fault("untrusted_authority")
        key = self._keys.get(record.key_id)  # type: ignore[arg-type]
        if key is None:
            raise _Fault("untrusted_key")
        try:
            key.verify(record.signature, record.signing_input())  # type: ignore[arg-type]
        except InvalidSignature:
            raise _Fault("invalid_signature") from None

    def _check_history(self, hashes: tuple[str, ...]) -> None:
        seen = self._seen
        if hashes[: len(seen)] == seen:
            return
        if len(hashes) < len(seen) and seen[: len(hashes)] == hashes:
            raise _Fault("rollback_detected")
        raise _Fault("fork_detected")

    def _check_anchor(self, hashes: tuple[str, ...]) -> None:
        if self._anchor is None:
            return
        if len(hashes) < self._anchor.record_count:
            raise _Fault("rollback_detected")
        if hashes[self._anchor.record_count - 1] != self._anchor.head_hash:
            raise _Fault("fork_detected")

    def _detection(self) -> str:
        return ROLLBACK_DETECTION_ANCHOR if self._anchor is not None else ROLLBACK_DETECTION_NONE

    def _fault_state(self, code: str) -> JournalState:
        return JournalState(
            True, None, code, False, True, 0, GENESIS_HASH, self._detection()
        )

    def _stopped_state(
        self, generation: Optional[int], reason: str, terminal: bool,
        records: tuple[JournalRecord, ...],
    ) -> JournalState:
        return JournalState(
            True, generation, reason, terminal, False, len(records),
            records[-1].record_hash() if records else GENESIS_HASH, self._detection(),
        )


def _write_all(fd: int, raw: bytes) -> None:
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:])
        if written <= 0:
            raise OSError("Incomplete journal write.")
        offset += written
