"""Dormant descriptor provenance checks, not containment or execution authority."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import fcntl
import os
import platform
import stat
import sys
import threading

from gvai.linux_containment_stop import CleanupEvidence, OwnedContainment


_CGROUP2_SUPER_MAGIC = 0x63677270


class ContainmentIdentityRejected(ValueError):
    """Required descriptor provenance could not be established."""


@dataclass(frozen=True)
class ContainmentIdentity:
    """Device/inode of an independently selected and pinned cgroup directory."""

    device: int
    inode: int


class _LinuxStatFS64(ctypes.Structure):
    # Linux 64-bit statfs ABI on the explicitly supported architectures below.
    _fields_ = [
        ("f_type", ctypes.c_long), ("f_bsize", ctypes.c_long),
        ("f_blocks", ctypes.c_ulong), ("f_bfree", ctypes.c_ulong),
        ("f_bavail", ctypes.c_ulong), ("f_files", ctypes.c_ulong),
        ("f_ffree", ctypes.c_ulong), ("f_fsid", ctypes.c_int * 2),
        ("f_namelen", ctypes.c_long), ("f_frsize", ctypes.c_long),
        ("f_flags", ctypes.c_long), ("f_spare", ctypes.c_long * 4),
    ]


def _filesystem_type(fd: int) -> int:
    if (
        sys.platform != "linux" or platform.machine() not in ("x86_64", "aarch64")
        or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8
    ):
        raise ContainmentIdentityRejected("Unsupported statfs ABI.")
    library = ctypes.CDLL(None, use_errno=True)
    call = library.fstatfs
    call.argtypes = [ctypes.c_int, ctypes.POINTER(_LinuxStatFS64)]
    call.restype = ctypes.c_int
    result = _LinuxStatFS64()
    if call(fd, ctypes.byref(result)) != 0:
        raise OSError(ctypes.get_errno(), "Descriptor filesystem check failed.")
    return result.f_type


def _duplicate(fd: int) -> int:
    return fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 0)


def _metadata(fd: int, *, directory: bool, writable: bool = False):
    metadata = os.fstat(fd)
    correct_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not correct_type(metadata.st_mode) or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022 or metadata.st_nlink < 1
        or _filesystem_type(fd) != _CGROUP2_SUPER_MAGIC
    ):
        raise ContainmentIdentityRejected("Unsafe or non-cgroup-v2 descriptor.")
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    if flags & os.O_PATH:
        raise ContainmentIdentityRejected("O_PATH is not a control handle.")
    access = flags & os.O_ACCMODE
    permitted = (os.O_WRONLY, os.O_RDWR) if writable else (os.O_RDONLY, os.O_RDWR)
    if access not in permitted:
        raise ContainmentIdentityRejected("Incorrect descriptor access.")
    return metadata


def _same(left, right) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


class ValidatedContainmentDescriptors:
    """Retain validated descriptors and provide an explicit stop-only binding.

    Construction is trusted-parent-only. No worker-supplied descriptors or
    identities may reach this interface. Validation is a point-in-time check.
    """

    def __init__(
        self, *, directory_fd: int, kill_fd: int, events_fd: int,
        expected: ContainmentIdentity,
    ):
        sources = (directory_fd, kill_fd, events_fd)
        if (
            any(type(fd) is not int or fd < 0 for fd in sources)
            or len(set(sources)) != 3
            or type(expected) is not ContainmentIdentity
            or type(expected.device) is not int or expected.device < 0
            or type(expected.inode) is not int or expected.inode <= 0
        ):
            raise ContainmentIdentityRejected("Distinct descriptors and explicit identity required.")
        self._lock = threading.Lock()
        self._fds = []
        self._closed = False
        self._identity = expected
        try:
            # All further checks use retained duplicates, never caller FD numbers.
            for fd in sources:
                self._fds.append(_duplicate(fd))
            directory, kill, events = self._fds
            directory_metadata = _metadata(directory, directory=True)
            if (
                directory_metadata.st_dev != expected.device
                or directory_metadata.st_ino != expected.inode
            ):
                raise ContainmentIdentityRejected("Pinned directory identity mismatch.")
            kill_metadata = _metadata(kill, directory=False, writable=True)
            events_metadata = _metadata(events, directory=False)
            if (
                kill_metadata.st_dev != expected.device
                or events_metadata.st_dev != expected.device
                or _same(kill_metadata, events_metadata)
            ):
                raise ContainmentIdentityRejected("Mismatched control handles.")
            for name, writable, supplied in (
                ("cgroup.kill", True, kill_metadata),
                ("cgroup.events", False, events_metadata),
            ):
                # Fixed names only, relative to the retained cgroup directory.
                reference = os.open(
                    name,
                    (os.O_WRONLY if writable else os.O_RDONLY)
                    | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                    dir_fd=directory,
                )
                try:
                    observed = _metadata(reference, directory=False, writable=writable)
                    if not _same(supplied, observed):
                        raise ContainmentIdentityRejected("Control file identity mismatch.")
                finally:
                    os.close(reference)
        except BaseException as exc:
            self._closed = True
            self._release()
            if not isinstance(exc, Exception):
                raise
            raise ContainmentIdentityRejected("Descriptor provenance validation failed.") from exc

    @property
    def identity(self) -> ContainmentIdentity:
        with self._lock:
            if self._closed:
                raise ContainmentIdentityRejected("Validated descriptors are closed.")
            return self._identity

    def bind_stop(self, *, child_pidfds: tuple[int, ...]) -> _ValidatedStopBinding:
        """Duplicate checked controls under the same lock as validator closure.

        Child identity/membership remains a trusted-parent prerequisite.
        Construction never invokes stop or registers with a controller.
        """
        with self._lock:
            if self._closed:
                raise ContainmentIdentityRejected("Validated descriptors are closed.")
            if (
                type(child_pidfds) is not tuple or not child_pidfds
                or any(type(fd) is not int or fd < 0 for fd in child_pidfds)
                or len(set(child_pidfds)) != len(child_pidfds)
                or any(fd in self._fds for fd in child_pidfds)
            ):
                raise ContainmentIdentityRejected("Distinct parent-owned child pidfds required.")
            return _ValidatedStopBinding(self._fds, child_pidfds)

    def _release(self) -> None:
        descriptors, self._fds = self._fds, []
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError:
                # Never retry close: an FD number may already have been reused.
                pass

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                self._release()


class _ValidatedStopBinding:
    """Own a directory pin and an existing adapter; no public raw-FD handoff."""

    def __init__(self, validated, children):
        self._lock = threading.Lock()
        self._closed = False
        self._directory = None
        self._adapter = None
        adapter = None
        initialized = False
        try:
            self._directory = _duplicate(validated[0])
            # Keep the instance reachable if the legacy constructor is interrupted.
            adapter = OwnedContainment.__new__(OwnedContainment)
            adapter.__init__(
                kill_fd=validated[1], events_fd=validated[2], child_pidfds=children,
            )
            initialized = True
            self._adapter = adapter
        except BaseException as exc:
            self._closed = True
            if adapter is not None and (initialized or not isinstance(exc, Exception)):
                # The adapter cleans ordinary constructor exceptions itself, but
                # not BaseException cancellation. Close each retained FD once.
                for fd in getattr(adapter, "_fds", ()):
                    _close_once(fd)
            if self._directory is not None:
                _close_once(self._directory)
            raise

    def stop(self) -> CleanupEvidence:
        with self._lock:
            if self._closed:
                return CleanupEvidence("uncertain")
            return self._adapter.stop()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                try:
                    self._adapter.close()
                finally:
                    _close_once(self._directory)


def _close_once(fd):
    try:
        os.close(fd)
    except OSError:
        pass
