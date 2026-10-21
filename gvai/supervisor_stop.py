"""Disconnected stop-only controller. No admission, dispatch or publication API."""

from dataclasses import dataclass
import fcntl
import json
import os
import stat
import threading

from gvai.linux_containment_stop import CleanupEvidence, OwnedContainment


MAX_GENERATION = 2**63 - 1
_RECORD = "stop.json"
_PENDING = "stop.pending"
_INTENT = "stop.intent"


@dataclass(frozen=True)
class StopState:
    generation: int | None
    uncertain: bool
    stopped: bool = True


@dataclass(frozen=True)
class StopReport:
    state: StopState
    durable: bool
    cleanup: CleanupEvidence

    @property
    def status(self) -> str:
        return "uncertain" if self.state.uncertain or not self.durable else self.cleanup.status

    @property
    def allowed(self) -> bool:
        return False

    @property
    def authenticated(self) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate journal field.")
        result[key] = value
    return result


def _write_all(fd, raw):
    offset = 0
    while offset < len(raw):
        written = os.write(fd, raw[offset:])
        if written <= 0:
            raise OSError("Incomplete journal write.")
        offset += written


class StopJournal:
    """Single-owner local journal in an independently protected directory FD.

    Missing state has unknown generation, never a freshly reset generation.
    No initialize/unstop/recovery method is provided.
    """

    def __init__(self, directory_fd: int):
        if type(directory_fd) is not int or directory_fd < 0:
            raise ValueError("A parent-owned directory descriptor is required.")
        self._mutex = threading.Lock()
        self._dir = os.dup(directory_fd)
        self._lock_fd = None
        self._closed = False
        self._failed = False
        self._state = StopState(None, True)
        try:
            metadata = os.fstat(self._dir)
            if (
                not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o022
            ):
                raise ValueError("Journal directory must be privately administered.")
            self._lock_fd = os.open(
                "stop.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=self._dir,
            )
            metadata = os.fstat(self._lock_fd)
            if (
                not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
            ):
                raise ValueError("Invalid journal lock.")
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._state = self._load()
        except Exception:
            if self._lock_fd is not None:
                os.close(self._lock_fd)
            os.close(self._dir)
            raise

    def _load(self) -> StopState:
        try:
            # Neither rename nor a failed directory sync may erase crash evidence.
            for name in (_PENDING, _INTENT):
                try:
                    os.stat(name, dir_fd=self._dir, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError("Incomplete journal commit.")
            try:
                fd = os.open(
                    _RECORD, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=self._dir,
                )
            except FileNotFoundError:
                return StopState(None, True)
            try:
                metadata = os.fstat(fd)
                if (
                    not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
                ):
                    raise ValueError("Unsafe journal record.")
                raw = os.read(fd, 4097)
            finally:
                os.close(fd)
            if len(raw) > 4096:
                raise ValueError("Oversized journal.")
            value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique)
            if (
                type(value) is not dict
                or set(value) != {"version", "stopped", "generation", "uncertain"}
                or type(value["version"]) is not int or value["version"] != 1
                or value["stopped"] is not True or type(value["uncertain"]) is not bool
            ):
                raise ValueError("Invalid journal.")
            generation = value["generation"]
            if generation is not None and (
                type(generation) is not int or not 0 <= generation <= MAX_GENERATION
            ):
                raise ValueError("Invalid generation.")
            return StopState(generation, value["uncertain"] or generation in (None, MAX_GENERATION))
        except Exception:
            self._failed = True
            return StopState(None, True)

    def latch(self) -> tuple[StopState, bool]:
        with self._mutex:
            if self._closed or self._failed:
                self._state = StopState(self._state.generation, True)
                return self._state, False
            # Every valid record is already stopped. Duplicate STOP is idempotent.
            raw = json.dumps({
                "version": 1, "stopped": True, "generation": self._state.generation,
                "uncertain": self._state.uncertain,
            }, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
            fd = None
            try:
                fd = os.open(
                    _INTENT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=self._dir,
                )
                _write_all(fd, b"STOP\n")
                os.fsync(fd)
                os.close(fd)
                fd = None
                os.fsync(self._dir)
                fd = os.open(
                    _PENDING, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=self._dir,
                )
                _write_all(fd, raw)
                os.fsync(fd)
                os.close(fd)
                fd = None
                os.replace(_PENDING, _RECORD, src_dir_fd=self._dir, dst_dir_fd=self._dir)
                os.fsync(self._dir)
                # Only a fully durable record permits removal of crash evidence.
                os.unlink(_INTENT, dir_fd=self._dir)
                try:
                    os.fsync(self._dir)
                except OSError:
                    # Data is already durable; a resurrected intent on restart
                    # is conservative uncertainty, never a false commit.
                    pass
                return self._state, True
            except Exception:
                self._failed = True
                self._state = StopState(self._state.generation, True)
                return self._state, False
            finally:
                if fd is not None:
                    os.close(fd)

    def read(self) -> StopState:
        with self._mutex:
            return StopState(self._state.generation, self._state.uncertain or self._closed)

    def close(self) -> None:
        with self._mutex:
            if not self._closed:
                self._closed = True
                os.close(self._lock_fd)
                os.close(self._dir)


class StopController:
    """Trusted-parent-only object; neither its methods nor handles are worker RPCs."""

    def __init__(self, journal: StopJournal):
        if type(journal) is not StopJournal:
            raise ValueError("A protected journal is required.")
        self._journal = journal
        self._lock = threading.Lock()
        self._containments = []
        self._stopped = True

    def register(self, containment: OwnedContainment) -> StopReport:
        if type(containment) is not OwnedContainment:
            raise ValueError("Parent-owned containment is required.")
        with self._lock:
            if not any(item is containment for item in self._containments):
                self._containments.append(containment)
            # Registration never admits work; even late registration stops all.
            return self._stop()

    def request_stop(self) -> StopReport:
        with self._lock:
            return self._stop()

    def _stop(self) -> StopReport:
        self._stopped = True
        evidence = []
        for containment in self._containments:
            try:
                evidence.append(containment.stop())
            except Exception:
                evidence.append(CleanupEvidence("uncertain"))
        # Emergency termination must not wait for potentially failing storage.
        try:
            state, durable = self._journal.latch()
        except Exception:
            state, durable = StopState(None, True), False
        if not evidence or any(item.status == "uncertain" for item in evidence):
            cleanup = CleanupEvidence("uncertain")
        else:
            cleanup = CleanupEvidence(
                "terminated" if all(item.status == "terminated" for item in evidence) else "pending",
                all(item.kill_requested for item in evidence),
                all(item.empty for item in evidence), all(item.reaped for item in evidence),
            )
        return StopReport(state, durable, cleanup)
