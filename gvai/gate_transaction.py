"""Local experimental gate transactions, not independent rollback protection."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat

from gvai import experimental_stop_latch as sl

LIMIT = 16384
MAX_REVISION = 2**53
RECEIPT = "transaction.json"
INTENT = "transaction.intent"
LOCK = "transaction.lock"
FILES = ("anchor.json", "store.json", RECEIPT)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(raw):
    return hashlib.sha256(b"GVAI-GATE-TRANSACTION-V1\n" + raw).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_transaction_field")
            result[key] = value
        return result

    if len(raw) > LIMIT:
        raise ValueError("transaction_too_large")
    value = json.loads(raw, object_pairs_hook=pairs)
    if canonical(value) != raw:
        raise ValueError("noncanonical_transaction")
    return value


class GateTransaction:
    """One exclusive local writer; unresolved artifacts are never repaired."""

    def __init__(self, directory, latch_id, keys, phase=lambda name: None):
        self.directory = os.path.abspath(directory)
        self.latch_id, self.keys, self.phase = latch_id, keys, phase
        self.writer = None
        self.fault = False
        self.receipt = None
        self.dirfd = None
        self.dirfd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            directory_info = os.fstat(self.dirfd)
            if directory_info.st_uid != os.geteuid() or directory_info.st_mode & 0o077:
                raise ValueError("unsafe_gate_directory")
            self.writer = self._open(LOCK, os.O_RDWR)
            fcntl.flock(self.writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._confirm()
        except BlockingIOError:
            self.close()
            raise ValueError("gate_writer_busy") from None
        except Exception:
            self.fault = True

    @classmethod
    def provision(cls, directory, latch_id):
        """Offline genesis only. Never accepts or migrates an existing directory."""
        if not isinstance(latch_id, str) or not sl._IDENTIFIER.fullmatch(latch_id):
            raise ValueError("invalid_latch_id")
        directory = os.path.abspath(directory)
        os.mkdir(directory, 0o700)
        parent = os.open(os.path.dirname(directory), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            anchor = canonical({"sequence": 0, "digest": sl.GENESIS_HEAD.digest})
            store = canonical(None)
            receipt = cls._receipt(latch_id, 0, None, anchor, store, None)
            for name, raw in (
                (LOCK, b""), ("gate_key.seed", secrets.token_bytes(32)),
                ("anchor.json", anchor), ("store.json", store),
                (RECEIPT, canonical(receipt)),
            ):
                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
                try:
                    cls._write(fd, raw)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            os.fsync(dirfd)
        finally:
            os.close(dirfd)

    @staticmethod
    def _receipt(latch_id, revision, envelope, anchor, store, previous):
        return dict(version=1, latch_id=latch_id, revision=revision, command=envelope,
                    anchor_hash=digest(anchor), store_hash=digest(store), previous=previous)

    @staticmethod
    def _write(fd, raw):
        while raw:
            count = os.write(fd, raw)
            if count <= 0:
                raise OSError("short_transaction_write")
            raw = raw[count:]

    def _open(self, name, flags):
        fd = os.open(name, flags | os.O_NOFOLLOW, 0o600, dir_fd=self.dirfd)
        try:
            self._identity(name, fd)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _identity(self, name, fd):
        held = os.fstat(fd)
        named = os.stat(name, dir_fd=self.dirfd, follow_symlinks=False)
        if (not stat.S_ISREG(held.st_mode) or held.st_nlink != 1
                or held.st_uid != os.geteuid() or held.st_mode & 0o077
                or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)):
            raise ValueError("unsafe_gate_transaction_file")

    def _read(self, name, sync=False):
        fd = self._open(name, os.O_RDONLY)
        try:
            raw = os.read(fd, LIMIT + 1)
            if len(raw) > LIMIT:
                raise ValueError("transaction_too_large")
            if sync:
                os.fsync(fd)
                os.fsync(self.dirfd)
                self._identity(name, fd)
                os.lseek(fd, 0, os.SEEK_SET)
                if os.read(fd, LIMIT + 1) != raw:
                    raise ValueError("gate_readback_mismatch")
            self._identity(name, fd)
            return raw
        finally:
            os.close(fd)

    def _check_clean(self):
        self._identity(LOCK, self.writer)
        for name in (INTENT, *(n + ".tmp" for n in FILES)):
            try:
                os.stat(name, dir_fd=self.dirfd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("unresolved_gate_transaction")

    def _validate(self, receipt, anchor, store):
        head = decode(anchor)
        if (type(head) is not dict or set(head) != {"sequence", "digest"}
                or type(head["sequence"]) is not int or not 0 <= head["sequence"] <= 2**53
                or type(head["digest"]) is not str or len(head["digest"]) != 64
                or any(c not in "0123456789abcdef" for c in head["digest"])):
            raise ValueError("invalid_gate_anchor")
        if (type(receipt) is not dict or set(receipt) != {
                "version", "latch_id", "revision", "command", "anchor_hash", "store_hash", "previous"}
                or type(receipt["version"]) is not int or receipt["version"] != 1
                or receipt["latch_id"] != self.latch_id
                or type(receipt["revision"]) is not int
                or not 0 <= receipt["revision"] <= MAX_REVISION
                or receipt["anchor_hash"] != digest(anchor)
                or receipt["store_hash"] != digest(store)):
            raise ValueError("invalid_gate_receipt")
        envelope = decode(store)
        if receipt["command"] != envelope:
            raise ValueError("gate_command_mismatch")
        if receipt["revision"] == 0:
            if (envelope is not None or receipt["previous"] is not None
                    or head != {"sequence": 0, "digest": sl.GENESIS_HEAD.digest}):
                raise ValueError("invalid_gate_genesis")
        else:
            previous = receipt["previous"]
            if type(previous) is not str or len(previous) != 64 or any(c not in "0123456789abcdef" for c in previous):
                raise ValueError("invalid_gate_predecessor")
            command = sl.parse_command(envelope)
            if (command.latch_id != self.latch_id or not self.keys.verify(command)
                    or head != {"sequence": command.sequence, "digest": command.digest()}):
                raise ValueError("invalid_gate_command")

    def _confirm(self, sync=True):
        self._check_clean()
        anchor, store, raw = (self._read(n, sync) for n in FILES)
        receipt = decode(raw)
        self._validate(receipt, anchor, store)
        if self.receipt is not None and receipt != self.receipt:
            raise ValueError("gate_receipt_changed")
        self.receipt = receipt
        return decode(anchor), decode(store)

    def load(self):
        if self.fault or self.writer is None:
            raise ValueError("gate_transaction_fault")
        try:
            return self._confirm(sync=False)
        except Exception:
            self.fault = True
            raise

    def _replace(self, name, raw):
        temporary = name + ".tmp"
        fd = self._open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL)
        try:
            self._write(fd, raw)
            self.phase(name + ":written")
            self.phase(name + ":before_file_sync")
            os.fsync(fd)
            self.phase(name + ":file_synced")
            self._identity(temporary, fd)
            self.phase(name + ":before_replace")
            os.replace(os.path.join(self.directory, temporary), os.path.join(self.directory, name))
            self.phase(name + ":replaced")
            self._identity(name, fd)
            self.phase(name + ":before_directory_sync")
            os.fsync(self.dirfd)
            self.phase(name + ":directory_synced")
            self.phase(name + ":before_readback")
            os.lseek(fd, 0, os.SEEK_SET)
            if os.read(fd, LIMIT + 1) != raw:
                raise ValueError("gate_readback_mismatch")
            self._identity(name, fd)
            self.phase(name + ":read_back")
        finally:
            os.close(fd)

    def commit(self, command):
        self.load()
        if self.receipt["revision"] == MAX_REVISION:
            self.fault = True
            raise ValueError("gate_revision_exhausted")
        envelope = sl.command_envelope(command)
        anchor = canonical({"sequence": command.sequence, "digest": command.digest()})
        store = canonical(envelope)
        receipt = self._receipt(self.latch_id, self.receipt["revision"] + 1, envelope,
                                anchor, store, digest(canonical(self.receipt)))
        try:
            self.phase("before_intent")
            fd = self._open(INTENT, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            try:
                self._write(fd, canonical(receipt))
                self.phase("intent_written")
                self.phase("before_intent_sync")
                os.fsync(fd)
                self.phase("intent_file_synced")
            finally:
                os.close(fd)
            os.fsync(self.dirfd)
            self.phase("intent_durable")
            if self._read(INTENT, sync=True) != canonical(receipt):
                raise ValueError("gate_intent_readback_mismatch")
            for name, raw in zip(FILES, (anchor, store, canonical(receipt))):
                self._replace(name, raw)
            self.phase("before_cleanup")
            os.unlink(os.path.join(self.directory, INTENT))
            self.phase("intent_removed")
            os.fsync(self.dirfd)
            self.phase("cleanup_synced")
            self.receipt = receipt
            self._confirm()
            self.phase("before_ack")
        except BaseException:
            self.fault = True
            raise

    def close(self):
        if self.writer is not None:
            os.close(self.writer)
            self.writer = None
        if self.dirfd is not None:
            os.close(self.dirfd)
            self.dirfd = None

    def __del__(self):
        self.close()
