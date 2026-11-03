"""Disconnected Linux local persistence. No independent rollback resistance."""

from __future__ import annotations

import fcntl
import json
import os
import stat
from dataclasses import fields
from threading import Lock
from typing import Callable

from gvai import stop_generation_authority as sa
from gvai.experimental_stop_latch import StopLatchKeyring, command_envelope, parse_command

MAX_FILE_BYTES = 512 * 1024
STATE = "authority.json"
LOCK = "authority.lock"
INTENT = "authority.intent"
PENDING = "authority.pending"


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
    ).encode("ascii")


def encode_snapshot(snapshot: sa.AuthoritySnapshot) -> bytes:
    events = []
    for event in snapshot.events:
        item = {field.name: getattr(event, field.name) for field in fields(sa.AuthorityEvent)}
        item["command"] = command_envelope(event.command) if event.command is not None else None
        events.append(item)
    raw = _canonical({
        "version": 1, "authority_id": snapshot.authority_id,
        "latch_id": snapshot.latch_id, "events": events,
    })
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("authority_file_oversized")
    return raw


def decode_snapshot(raw: bytes) -> sa.AuthoritySnapshot:
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FILE_BYTES:
        raise ValueError("invalid_authority_file_size")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("duplicate_field")
            result[name] = value
        return result

    def reject(value: str) -> None:
        raise ValueError("nonfinite_json")

    try:
        body = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=reject)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("malformed_authority_json") from exc
    if (
        type(body) is not dict
        or set(body) != {"version", "authority_id", "latch_id", "events"}
        or type(body["version"]) is not int or body["version"] != 1
        or type(body["events"]) is not list or len(body["events"]) > sa.MAX_EVENTS
    ):
        raise ValueError("invalid_authority_fields")
    expected = {field.name for field in fields(sa.AuthorityEvent)}
    events = []
    for item in body["events"]:
        if type(item) is not dict or set(item) != expected:
            raise ValueError("invalid_event_fields")
        item["command"] = parse_command(item["command"]) if item["command"] is not None else None
        events.append(sa.AuthorityEvent(**item))
    snapshot = sa.AuthoritySnapshot(body["authority_id"], body["latch_id"], tuple(events))
    if raw != encode_snapshot(snapshot):
        raise ValueError("noncanonical_authority_json")
    return snapshot


class FilesystemAuthorityAdapter:
    """One exclusive writer session on a private, preprovisioned Linux directory.

    Constructor failure denies startup. Any failed I/O poisons this instance;
    restart rejects leftover intent/pending evidence. No implicit provisioning,
    repair, checkpoint advancement, network calls or reopening.
    """

    def __init__(
        self, directory: str, authority_id: str, latch_id: str, keys: StopLatchKeyring,
        *, phase: Callable[[str], None] | None = None,
    ) -> None:
        self._dir = -1
        self._writer = -1
        self._mutex = Lock()
        self._fault = False
        self._evidence: sa.AuthoritySnapshot | None = None
        self._seen: tuple[sa.AuthorityEvent, ...] = ()
        self._authority_id, self._latch_id, self._keys = authority_id, latch_id, keys
        self._phase = phase if phase is not None else lambda name: None
        try:
            self._dir = self._open_directory(directory)
            self._writer = self._open_file(LOCK, os.O_RDWR)
            fcntl.flock(self._writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._check_incomplete()
            self._confirmed_load()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _open_directory(directory: str) -> int:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(fd)
            raise ValueError("unsafe_authority_directory")
        return fd

    def _open_file(self, name: str, flags: int) -> int:
        fd = os.open(
            name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            0o600, dir_fd=self._dir,
        )
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
        ):
            os.close(fd)
            raise ValueError("unsafe_authority_file")
        return fd

    @classmethod
    def provision(
        cls, directory: str, initial: sa.AuthoritySnapshot, keys: StopLatchKeyring,
    ) -> None:
        """Explicit trusted offline initialization of an empty private directory.

        Never overwrites state. A provisioning failure leaves evidence and
        requires operator investigation, not automatic reuse of partial files.
        The directory and its parent must already be durably provisioned.
        """
        sa.validate_authority_snapshot(initial, initial.authority_id, initial.latch_id, keys)
        fd = cls._open_directory(directory)
        try:
            # Empty-directory initialization is an operator-only, single-session act.
            if os.listdir(fd):
                raise ValueError("authority_directory_not_empty")
            for name, raw in ((LOCK, b""), (STATE, encode_snapshot(initial))):
                out = os.open(
                    name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=fd,
                )
                try:
                    cls._write_all(out, raw)
                    os.fsync(out)
                finally:
                    os.close(out)
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _write_all(fd: int, raw: bytes) -> None:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short_authority_write")
            view = view[count:]

    def _read(self, fd: int) -> bytes:
        os.lseek(fd, 0, os.SEEK_SET)
        raw = bytearray()
        while len(raw) <= MAX_FILE_BYTES:
            chunk = os.read(fd, min(65536, MAX_FILE_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        return bytes(raw)

    def _verify_identity(
        self, name: str, fd: int, identity: tuple[int, int] | None = None,
    ) -> None:
        held = os.fstat(fd)
        named = os.stat(name, dir_fd=self._dir, follow_symlinks=False)
        for info in (held, named):
            if (
                not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ValueError("unsafe_authority_file")
        if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
            raise ValueError("authority_file_substituted")
        if identity is not None and (held.st_dev, held.st_ino) != identity:
            raise ValueError("authority_descriptor_substituted")

    def _confirmed_load(self, retained: int | None = None) -> sa.AuthoritySnapshot:
        self._check_incomplete()
        fd = retained if retained is not None else self._open_file(STATE, os.O_RDONLY)
        try:
            info = os.fstat(fd)
            identity = (info.st_dev, info.st_ino)
            self._verify_identity(STATE, fd, identity)
            raw = self._read(fd)
            snapshot = decode_snapshot(raw)
            self._validate(snapshot)
            self._phase("before_state_sync")
            self._verify_identity(STATE, fd, identity)
            os.fsync(fd)
            os.fsync(self._dir)
            self._phase("before_readback")
            self._verify_identity(STATE, fd, identity)
            if self._read(fd) != raw:
                raise ValueError("authority_readback_mismatch")
            self._verify_identity(STATE, fd, identity)
            self._evidence = snapshot
            self._seen = snapshot.events
            return snapshot
        finally:
            if retained is None:
                os.close(fd)

    def _check_incomplete(self) -> None:
        for name in (INTENT, PENDING):
            try:
                os.stat(name, dir_fd=self._dir, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("incomplete_authority_commit")
        lock_info = os.stat(LOCK, dir_fd=self._dir, follow_symlinks=False)
        held = os.fstat(self._writer)
        if (lock_info.st_dev, lock_info.st_ino) != (held.st_dev, held.st_ino):
            raise ValueError("authority_lock_substituted")

    def _validate(self, snapshot: sa.AuthoritySnapshot) -> None:
        sa.validate_authority_snapshot(
            snapshot, self._authority_id, self._latch_id, self._keys, seen=self._seen,
        )

    def load(self) -> sa.AuthoritySnapshot:
        with self._mutex:
            if self._fault or self._dir < 0:
                raise ValueError("authority_adapter_fault")
            try:
                return self._confirmed_load()
            except BaseException:
                self._fault = True
                self._evidence = None
                raise

    def compare_and_swap(
        self, expected: sa.AuthoritySnapshot, proposed: sa.AuthoritySnapshot,
    ) -> str:
        with self._mutex:
            if self._fault or self._dir < 0:
                raise ValueError("authority_adapter_fault")
            try:
                current = self._confirmed_load()
                if current != expected:
                    return "CONFLICT"
                if (
                    proposed.events[:-1] != expected.events
                    or len(proposed.events) != len(expected.events) + 1
                ):
                    raise ValueError("invalid_conditional_update")
                self._validate(proposed)
                raw = encode_snapshot(proposed)
                self._evidence = None
                self._phase("before_intent")
                out = self._open_file(INTENT, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                try:
                    self._write_all(out, raw)
                    self._phase("before_intent_sync")
                    os.fsync(out)
                finally:
                    os.close(out)
                os.fsync(self._dir)
                self._phase("intent_durable")
                out = self._open_file(PENDING, os.O_RDWR | os.O_CREAT | os.O_EXCL)
                try:
                    info = os.fstat(out)
                    identity = (info.st_dev, info.st_ino)
                    self._phase("before_pending_write")
                    self._write_all(out, raw)
                    self._phase("before_pending_sync")
                    os.fsync(out)
                    self._phase("pending_synced")
                    self._verify_identity(PENDING, out, identity)
                    os.replace(PENDING, STATE, src_dir_fd=self._dir, dst_dir_fd=self._dir)
                    self._phase("after_replace")
                    self._verify_identity(STATE, out, identity)
                    os.fsync(self._dir)
                    self._phase("replacement_synced")
                    self._verify_identity(STATE, out, identity)
                    if self._read(out) != raw:
                        raise ValueError("authority_readback_mismatch")
                    self._verify_identity(STATE, out, identity)
                    self._phase("before_intent_remove")
                    self._verify_identity(STATE, out, identity)
                    os.unlink(INTENT, dir_fd=self._dir)
                    self._phase("before_cleanup_sync")
                    os.fsync(self._dir)
                    self._phase("cleanup_synced")
                    confirmed = self._confirmed_load(out)
                    if confirmed != proposed:
                        raise ValueError("authority_readback_mismatch")
                    self._phase("before_ack")
                    self._verify_identity(STATE, out, identity)
                    if self._read(out) != raw:
                        raise ValueError("authority_readback_mismatch")
                    self._verify_identity(STATE, out, identity)
                    return "APPLIED"
                finally:
                    os.close(out)
            except BaseException:
                self._fault = True
                self._evidence = None
                raise

    def locally_durable(self, snapshot: sa.AuthoritySnapshot) -> bool:
        """Historical synchronization evidence for the latest confirmed snapshot.

        Does not reread disk or attest that storage remains unchanged. A new
        update, fault or close invalidates evidence; mismatched heads return false.
        """
        with self._mutex:
            if self._fault or self._dir < 0:
                raise ValueError("authority_adapter_fault")
            if type(snapshot) is not sa.AuthoritySnapshot:
                return False
            return self._evidence == snapshot

    def close(self) -> None:
        with self._mutex:
            for attribute in ("_writer", "_dir"):
                fd = getattr(self, attribute)
                if fd >= 0:
                    os.close(fd)
                    setattr(self, attribute, -1)
            self._evidence = None

    def __enter__(self) -> FilesystemAuthorityAdapter:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
