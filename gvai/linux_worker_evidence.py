"""Read-only, descriptor-relative worker observations; never grants authority."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import ctypes
import os
import platform
import stat
import sys
import time
from typing import Protocol

from gvai.launcher_worker_contract import EvidenceRequest
from gvai.systemd_worker_profile import REQUIRED_NAMESPACES
from gvai.trusted_worker_entry import EntryIdentity, ObjectPin, _valid_request
from gvai.trusted_worker_entry import PROPOSED_WORKER_LABEL


MAX_FIELD_BYTES = 64 * 1024
MAX_FD_COUNT = 256
MAX_FD_TARGET_BYTES = 4096
MAX_WORKER_EVIDENCE_AGE_NS = 5_000_000_000

_PROC_SUPER_MAGIC = 0x9FA0
_CGROUP2_SUPER_MAGIC = 0x63677270
_NSFS_MAGIC = 0x6E736673


class ProcessField(Enum):
    STAT = "stat"
    STATUS = "status"
    UID_MAP = "uid_map"
    GID_MAP = "gid_map"
    SETGROUPS = "setgroups"
    CGROUP = "cgroup"
    APPARMOR_CURRENT = "apparmor_current"


class ObservationState(Enum):
    OBSERVED = "observed"
    UNVERIFIED = "unverified"
    FAILED = "failed"


class ObservationSource(Enum):
    PINNED_KERNEL_INTERFACES = "pinned-kernel-interfaces"
    INJECTED_TEST_READER = "injected-test-reader"


@dataclass(frozen=True)
class ProcessHandleContext:
    """Parent-supplied pinned handles; integer PID is correlation, not authority."""

    identity: EntryIdentity
    request: EvidenceRequest
    pidfd: int
    process_directory_fd: int
    cgroup_directory_fd: int
    expected_descriptors: tuple["DescriptorRecord", ...]
    expected_uid_map: tuple[tuple[int, int, int], ...]
    expected_gid_map: tuple[tuple[int, int, int], ...]
    expected_setgroups: str
    expected_namespaces: tuple["NamespaceRecord", ...]


@dataclass(frozen=True)
class DescriptorRecord:
    number: int
    target: str
    flags: int

    def __post_init__(self) -> None:
        if (
            type(self.number) is not int or self.number < 0
            or type(self.target) is not str or len(self.target) > MAX_FD_TARGET_BYTES
            or type(self.flags) is not int or self.flags < 0
        ):
            raise ValueError("Exact bounded descriptor expectation required.")


@dataclass(frozen=True)
class NamespaceRecord:
    name: str
    identity: ObjectPin


@dataclass(frozen=True)
class ProcessFacts:
    pid: int
    start_ticks: int
    uid: tuple[int, int, int, int]
    gid: tuple[int, int, int, int]
    no_new_privs: bool
    seccomp_mode: int
    capabilities: tuple[tuple[str, int], ...]
    uid_map: tuple[tuple[int, int, int], ...]
    gid_map: tuple[tuple[int, int, int], ...]
    setgroups: str
    apparmor_label: str
    namespaces: tuple[NamespaceRecord, ...]
    cgroup: ObjectPin
    cgroup_path: str
    cgroup_contains_pid: bool
    descriptors: tuple[DescriptorRecord, ...]


@dataclass(frozen=True)
class EvidenceCollection:
    state: ObservationState
    source: ObservationSource
    identity: EntryIdentity | None
    request: EvidenceRequest | None
    collected_at_ns: int | None
    facts: ProcessFacts | None
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


class ProcessEvidenceReader(Protocol):
    def read_field(self, field: ProcessField, max_bytes: int) -> bytes: ...

    def namespace_identities(self) -> tuple[NamespaceRecord, ...]: ...

    def cgroup_identity(self) -> ObjectPin: ...

    def cgroup_contains(self, pid: int) -> bool: ...

    def descriptor_inventory(self) -> tuple[DescriptorRecord, ...]: ...

    def pidfd_pid(self) -> int: ...

    def pidfd_alive(self) -> bool: ...


class _LinuxStatFS(ctypes.Structure):
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
        raise OSError("Unsupported Linux statfs ABI.")
    call = ctypes.CDLL(None, use_errno=True).fstatfs
    call.argtypes = [ctypes.c_int, ctypes.POINTER(_LinuxStatFS)]
    call.restype = ctypes.c_int
    result = _LinuxStatFS()
    if call(fd, ctypes.byref(result)) != 0:
        raise OSError(ctypes.get_errno(), "fstatfs failed.")
    return result.f_type


def _read_bounded(fd: int, limit: int) -> bytes:
    output = bytearray()
    while len(output) <= limit:
        chunk = os.read(fd, min(8192, limit + 1 - len(output)))
        if not chunk:
            break
        output.extend(chunk)
    if len(output) > limit:
        raise ValueError("Kernel observation exceeded its fixed byte limit.")
    return bytes(output)


def _open_components(directory_fd: int, components: tuple[str, ...], *, follow_final: bool = False) -> int:
    current = os.dup(directory_fd)
    try:
        for component in components[:-1]:
            if component in ("", ".", "..") or "/" in component:
                raise ValueError("Invalid fixed descriptor-relative component.")
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=current,
            )
            os.close(current)
            current = next_fd
        final = components[-1]
        if final in ("", ".", "..") or "/" in final:
            raise ValueError("Invalid fixed descriptor-relative leaf.")
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
        if not follow_final:
            flags |= os.O_NOFOLLOW
        result = os.open(final, flags, dir_fd=current)
        return result
    finally:
        os.close(current)


_FIELD_PATHS = {
    ProcessField.STAT: ("stat",),
    ProcessField.STATUS: ("status",),
    ProcessField.UID_MAP: ("uid_map",),
    ProcessField.GID_MAP: ("gid_map",),
    ProcessField.SETGROUPS: ("setgroups",),
    ProcessField.CGROUP: ("cgroup",),
    ProcessField.APPARMOR_CURRENT: ("attr", "current"),
}


class LinuxProcessEvidenceReader:
    """Fixed-procfs reader over parent-pinned process and cgroup descriptors.

    The supplied descriptors and their owner remain part of the trusted
    computing base. Construction does not authenticate their provenance.
    """

    def __init__(self, handles: ProcessHandleContext):
        if type(handles) is not ProcessHandleContext:
            raise ValueError("Parent-provided pinned process handles are required.")
        self._identity = handles.identity
        self._pidfd = self._process_fd = self._cgroup_fd = -1
        self._closed = False
        try:
            self._pidfd = os.dup(handles.pidfd)
            self._process_fd = os.dup(handles.process_directory_fd)
            self._cgroup_fd = os.dup(handles.cgroup_directory_fd)
            for fd in (self._pidfd, self._process_fd, self._cgroup_fd):
                os.set_inheritable(fd, False)
            if (
                not stat.S_ISDIR(os.fstat(self._process_fd).st_mode)
                or _filesystem_type(self._process_fd) != _PROC_SUPER_MAGIC
            ):
                raise OSError("Pinned process directory is not procfs.")
            cgroup_stat = os.fstat(self._cgroup_fd)
            expected = self._identity.cgroup
            if (
                not stat.S_ISDIR(cgroup_stat.st_mode)
                or (cgroup_stat.st_dev, cgroup_stat.st_ino) != (expected.device, expected.inode)
                or _filesystem_type(self._cgroup_fd) != _CGROUP2_SUPER_MAGIC
            ):
                raise OSError("Pinned cgroup descriptor identity or filesystem mismatch.")
        except BaseException:
            self.close()
            raise

    def read_field(self, field: ProcessField, max_bytes: int) -> bytes:
        if (
            self._closed or type(field) is not ProcessField
            or type(max_bytes) is not int or not 0 < max_bytes <= MAX_FIELD_BYTES
        ):
            raise ValueError("Closed reader or non-allowlisted field/size.")
        descriptor = _open_components(self._process_fd, _FIELD_PATHS[field])
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError("Process observation is not a regular pseudo-file.")
            return _read_bounded(descriptor, max_bytes)
        finally:
            os.close(descriptor)

    def pidfd_pid(self) -> int:
        raw = self._read_pidfd_info()
        fields = _parse_key_values(raw, {"Pid"})
        value = fields.get("Pid")
        if value is None or not value.isdecimal() or int(value) <= 0:
            raise ValueError("pidfd does not identify a live process.")
        return int(value)

    def pidfd_alive(self) -> bool:
        import select

        poller = select.poll()
        poller.register(self._pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        return not bool(poller.poll(0))

    def _read_pidfd_info(self) -> bytes:
        if self._closed:
            raise ValueError("Reader is closed.")
        fd = os.open(
            f"/proc/self/fdinfo/{self._pidfd}",
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
        )
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("pidfd information is not a regular procfs file.")
            return _read_bounded(fd, 4096)
        finally:
            os.close(fd)

    def namespace_identities(self) -> tuple[NamespaceRecord, ...]:
        records = []
        for name in sorted(REQUIRED_NAMESPACES):
            fd = _open_components(self._process_fd, ("ns", name), follow_final=True)
            try:
                if _filesystem_type(fd) != _NSFS_MAGIC:
                    raise OSError("Namespace descriptor is not nsfs.")
                facts = os.fstat(fd)
                records.append(NamespaceRecord(name, ObjectPin(facts.st_dev, facts.st_ino)))
            finally:
                os.close(fd)
        return tuple(records)

    def cgroup_identity(self) -> ObjectPin:
        if self._closed or _filesystem_type(self._cgroup_fd) != _CGROUP2_SUPER_MAGIC:
            raise OSError("Pinned cgroup v2 descriptor unavailable.")
        facts = os.fstat(self._cgroup_fd)
        return ObjectPin(facts.st_dev, facts.st_ino)

    def cgroup_contains(self, pid: int) -> bool:
        if type(pid) is not int or pid <= 0:
            raise ValueError("Exact process identity required.")
        fd = _open_components(self._cgroup_fd, ("cgroup.procs",))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("cgroup.procs is not a regular pseudo-file.")
            raw = _read_bounded(fd, MAX_FIELD_BYTES)
        finally:
            os.close(fd)
        values = raw.decode("ascii", errors="strict").splitlines()
        if any(not item.isdecimal() for item in values):
            raise ValueError("Malformed cgroup process inventory.")
        return str(pid) in values

    def descriptor_inventory(self) -> tuple[DescriptorRecord, ...]:
        if self._closed:
            raise ValueError("Reader is closed.")
        fd_dir = _open_components(self._process_fd, ("fd",))
        try:
            first = self._scan_descriptor_directory(fd_dir)
            second = self._scan_descriptor_directory(fd_dir)
            if first != second:
                raise InterruptedError("Process FD inventory changed during observation.")
            return first
        finally:
            os.close(fd_dir)

    def _scan_descriptor_directory(self, fd_dir: int) -> tuple[DescriptorRecord, ...]:
        names = []
        with os.scandir(fd_dir) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > MAX_FD_COUNT:
                    raise ValueError("Process FD inventory exceeds its fixed limit.")
        if any(not item.isdecimal() for item in names) or len(set(names)) != len(names):
            raise ValueError("Malformed process FD inventory.")
        records = []
        for item in sorted(names, key=int):
            target = os.readlink(item, dir_fd=fd_dir)
            if len(target.encode("utf-8", errors="strict")) > MAX_FD_TARGET_BYTES:
                raise ValueError("FD target exceeds fixed limit.")
            info_fd = _open_components(self._process_fd, ("fdinfo", item))
            try:
                info = _parse_key_values(_read_bounded(info_fd, 4096), {"flags"})
            finally:
                os.close(info_fd)
            flags = info.get("flags")
            if flags is None:
                raise ValueError("FD info lacks flags.")
            records.append(DescriptorRecord(int(item), target, int(flags, 8)))
        return tuple(records)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        errors = []
        for fd in (self._pidfd, self._process_fd, self._cgroup_fd):
            if fd < 0:
                continue
            try:
                os.close(fd)
            except OSError as error:
                errors.append(error)
        if errors:
            raise errors[0]

    def __enter__(self) -> "LinuxProcessEvidenceReader":
        if self._closed:
            raise ValueError("Reader is closed.")
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def _parse_key_values(raw: bytes, allowed: set[str]) -> dict[str, str]:
    result = {}
    for line in raw.decode("ascii", errors="strict").splitlines():
        if ":" not in line:
            raise ValueError("Malformed key/value observation.")
        key, value = line.split(":", 1)
        key = key.strip()
        if key not in allowed:
            continue
        if key in result:
            raise ValueError("Duplicate observation field.")
        result[key] = value.strip()
    return result


def _parse_proc_stat(raw: bytes) -> tuple[int, int]:
    text = raw.decode("ascii", errors="strict").strip()
    left, separator, _ = text.partition(" (")
    closing = text.rfind(")")
    if not separator or closing <= len(left) + 1:
        raise ValueError("Malformed proc stat record.")
    if not left.isdecimal():
        raise ValueError("Malformed proc stat PID.")
    fields = text[closing + 1:].strip().split()
    if len(fields) <= 19 or not fields[19].isdecimal():
        raise ValueError("Missing proc stat start time.")
    return int(left), int(fields[19])


def _parse_process_status(raw: bytes) -> tuple[tuple[int, ...], tuple[int, ...], bool, int, tuple[tuple[str, int], ...]]:
    allowed = {"Uid", "Gid", "NoNewPrivs", "Seccomp", "CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"}
    values = _parse_key_values(raw, allowed)
    try:
        uid = tuple(int(item) for item in values["Uid"].split())
        gid = tuple(int(item) for item in values["Gid"].split())
        no_new_privs = values["NoNewPrivs"] == "1"
        if values["NoNewPrivs"] not in ("0", "1"):
            raise ValueError("Invalid NoNewPrivs.")
        seccomp = int(values["Seccomp"])
        caps = tuple((name, int(values[name], 16)) for name in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"))
    except (KeyError, ValueError) as error:
        raise ValueError("Incomplete or malformed process status.") from error
    if (
        len(uid) != 4 or len(gid) != 4 or min((*uid, *gid)) < 0
        or max((*uid, *gid)) >= (1 << 32) or seccomp not in (0, 1, 2)
        or any(value >= (1 << 64) for _, value in caps)
    ):
        raise ValueError("Out-of-range process credentials or seccomp mode.")
    return uid, gid, no_new_privs, seccomp, caps


def _parse_map(raw: bytes) -> tuple[tuple[int, int, int], ...]:
    rows = []
    for line in raw.decode("ascii", errors="strict").splitlines():
        parts = line.split()
        if len(parts) != 3 or any(not item.isdecimal() for item in parts):
            raise ValueError("Malformed UID/GID map.")
        inside, outside, length = map(int, parts)
        if (
            length <= 0 or inside + length > (1 << 32)
            or outside + length > (1 << 32)
        ):
            raise ValueError("UID/GID map range overflow.")
        rows.append((inside, outside, length))
    if not rows:
        raise ValueError("Empty UID/GID map.")
    return tuple(rows)


def _valid_id_map(value: object) -> bool:
    try:
        return type(value) is tuple and bool(value) and all(
            type(row) is tuple and len(row) == 3
            and all(type(item) is int and item >= 0 for item in row)
            and row[2] > 0
            and row[0] + row[2] <= (1 << 32)
            and row[1] + row[2] <= (1 << 32)
            for row in value
        )
    except (TypeError, OverflowError):
        return False


def _parse_apparmor_current(raw: bytes) -> str:
    value = raw.decode("utf-8", errors="strict").strip()
    if value.endswith(" (enforce)"):
        value = value[:-len(" (enforce)")]
    else:
        raise ValueError("AppArmor process label is not explicitly enforcing.")
    if not value or len(value) > 4096 or "\x00" in value:
        raise ValueError("Malformed AppArmor process label.")
    return value


def _parse_cgroup(raw: bytes) -> str:
    unified = []
    for line in raw.decode("ascii", errors="strict").splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3 or not parts[0].isdecimal():
            raise ValueError("Malformed cgroup membership record.")
        if parts[0] == "0":
            if parts[1] != "":
                raise ValueError("Malformed unified cgroup record.")
            path = parts[2]
            components = path.split("/")
            if (
                not path.startswith("/") or any(item in (".", "..") for item in components)
                or "\x00" in path
            ):
                raise ValueError("Noncanonical unified cgroup path.")
            unified.append(path)
    if len(unified) != 1:
        raise ValueError("Missing or duplicate unified cgroup membership.")
    return unified[0]


class KernelEvidenceCollector:
    """Collect and compare facts; never authenticates or authorizes them."""

    def collect(
        self, context: ProcessHandleContext, reader: ProcessEvidenceReader,
    ) -> EvidenceCollection:
        started_at_ns = time.monotonic_ns()
        source = (
            ObservationSource.PINNED_KERNEL_INTERFACES
            if type(reader) is LinuxProcessEvidenceReader
            else ObservationSource.INJECTED_TEST_READER
        )
        identity = context.identity if type(context) is ProcessHandleContext else None
        request = context.request if type(context) is ProcessHandleContext else None
        try:
            if (
                type(context) is not ProcessHandleContext
                or type(context.identity) is not EntryIdentity
                or type(context.request) is not EvidenceRequest
                or not _valid_request(context.request, context.identity)
                or context.request.spec.identity.boot != context.identity.boot
                or context.request.spec.identity.attempt != context.identity.attempt
                or context.request.spec.identity.service != context.identity.service
                or context.request.spec.identity.cgroup.device != context.identity.cgroup.device
                or context.request.spec.identity.cgroup.inode != context.identity.cgroup.inode
                or type(context.expected_descriptors) is not tuple
                or any(type(item) is not DescriptorRecord for item in context.expected_descriptors)
                or len({item.number for item in context.expected_descriptors}) != len(context.expected_descriptors)
                or not _valid_id_map(context.expected_uid_map)
                or not _valid_id_map(context.expected_gid_map)
                or context.expected_setgroups not in ("allow", "deny")
                or type(context.expected_namespaces) is not tuple
                or len(context.expected_namespaces) != len(REQUIRED_NAMESPACES)
                or any(type(item) is not NamespaceRecord for item in context.expected_namespaces)
                or any(
                    type(item.name) is not str or type(item.identity) is not ObjectPin
                    for item in context.expected_namespaces
                )
                or {item.name for item in context.expected_namespaces} != REQUIRED_NAMESPACES
            ):
                raise ValueError("Request and pinned process context mismatch.")
            if reader.pidfd_alive() is not True:
                raise ProcessLookupError("Pinned process lifetime is no longer live.")
            pid = reader.pidfd_pid()
            stat_first = _parse_proc_stat(reader.read_field(ProcessField.STAT, MAX_FIELD_BYTES))
            stat_second = _parse_proc_stat(reader.read_field(ProcessField.STAT, MAX_FIELD_BYTES))
            if stat_first != stat_second:
                raise ValueError("Process identity changed during observation.")
            stat_pid, start_ticks = stat_first
            if (
                pid != context.identity.process.pid
                or stat_pid != pid
                or start_ticks != context.identity.process.start_ticks
            ):
                raise ValueError("PID reuse or process-lifetime mismatch.")
            status_first = _parse_process_status(reader.read_field(ProcessField.STATUS, MAX_FIELD_BYTES))
            status_second = _parse_process_status(reader.read_field(ProcessField.STATUS, MAX_FIELD_BYTES))
            if status_first != status_second:
                raise ValueError("Process credentials or security state changed during observation.")
            uid, gid, nnp, seccomp, capabilities = status_first
            uid_map_first = _parse_map(reader.read_field(ProcessField.UID_MAP, MAX_FIELD_BYTES))
            uid_map_second = _parse_map(reader.read_field(ProcessField.UID_MAP, MAX_FIELD_BYTES))
            gid_map_first = _parse_map(reader.read_field(ProcessField.GID_MAP, MAX_FIELD_BYTES))
            gid_map_second = _parse_map(reader.read_field(ProcessField.GID_MAP, MAX_FIELD_BYTES))
            if uid_map_first != uid_map_second or gid_map_first != gid_map_second:
                raise ValueError("UID/GID maps changed during observation.")
            uid_map, gid_map = uid_map_first, gid_map_first
            setgroups_first = reader.read_field(ProcessField.SETGROUPS, MAX_FIELD_BYTES).decode("ascii", errors="strict").strip()
            setgroups_second = reader.read_field(ProcessField.SETGROUPS, MAX_FIELD_BYTES).decode("ascii", errors="strict").strip()
            if setgroups_first != setgroups_second:
                raise ValueError("setgroups state changed during observation.")
            setgroups = setgroups_first
            cgroup_path_first = _parse_cgroup(
                reader.read_field(ProcessField.CGROUP, MAX_FIELD_BYTES),
            )
            cgroup_path_second = _parse_cgroup(
                reader.read_field(ProcessField.CGROUP, MAX_FIELD_BYTES),
            )
            if cgroup_path_first != cgroup_path_second:
                raise ValueError("Cgroup path changed during observation.")
            if setgroups not in ("allow", "deny"):
                raise ValueError("Invalid setgroups state.")
            apparmor_first = _parse_apparmor_current(
                reader.read_field(ProcessField.APPARMOR_CURRENT, MAX_FIELD_BYTES),
            )
            apparmor_second = _parse_apparmor_current(
                reader.read_field(ProcessField.APPARMOR_CURRENT, MAX_FIELD_BYTES),
            )
            if apparmor_first != apparmor_second:
                raise ValueError("AppArmor label changed during observation.")
            apparmor_label = apparmor_first
            namespaces = reader.namespace_identities()
            if namespaces != reader.namespace_identities():
                raise ValueError("Namespace identities changed during observation.")
            if (
                type(namespaces) is not tuple
                or {item.name for item in namespaces if type(item) is NamespaceRecord} != REQUIRED_NAMESPACES
                or len(namespaces) != len(REQUIRED_NAMESPACES)
                or dict((item.name, item.identity) for item in namespaces)["pid"]
                != context.identity.process.pid_namespace
                or namespaces != context.expected_namespaces
            ):
                raise ValueError("Namespace identity mismatch.")
            cgroup = reader.cgroup_identity()
            member = reader.cgroup_contains(pid)
            if (
                cgroup != context.identity.cgroup or member is not True
                or cgroup != reader.cgroup_identity()
                or member != reader.cgroup_contains(pid)
            ):
                raise ValueError("Pinned cgroup mismatch or process membership absent.")
            descriptors = reader.descriptor_inventory()
            if (
                type(descriptors) is not tuple
                or descriptors != reader.descriptor_inventory()
                or descriptors != context.expected_descriptors
            ):
                raise ValueError("Descriptor inventory mismatch or unstable order.")
            if reader.pidfd_alive() is not True:
                raise ProcessLookupError("Process exited during evidence collection.")
            facts = ProcessFacts(
                pid, start_ticks, uid, gid, nnp, seccomp, capabilities,
                uid_map, gid_map, setgroups, apparmor_label, namespaces,
                cgroup, cgroup_path_first, True, descriptors,
            )
            if (
                uid != (context.request.spec.uid,) * 4
                or gid != (context.request.spec.gid,) * 4
                or not nnp
                or seccomp != 2
                or any(value != 0 for _, value in capabilities)
                or uid_map != context.expected_uid_map
                or gid_map != context.expected_gid_map
                or setgroups != context.expected_setgroups
                or apparmor_label != PROPOSED_WORKER_LABEL
            ):
                return EvidenceCollection(
                    ObservationState.FAILED, source, identity, request, None, facts,
                    ("Observed process state differs from supervisor-approved constraints.",),
                )
            completed_at_ns = time.monotonic_ns()
            if (
                completed_at_ns < started_at_ns
                or completed_at_ns - started_at_ns > MAX_WORKER_EVIDENCE_AGE_NS
            ):
                return EvidenceCollection(
                    ObservationState.UNVERIFIED, source, identity, request,
                    completed_at_ns, None,
                    ("Evidence collection exceeded its fixed freshness window.",),
                )
            # Structural consistency is not trusted authentication.
            return EvidenceCollection(
                ObservationState.UNVERIFIED, source, identity, request,
                completed_at_ns, facts,
                ("Read-only observations are not authenticated runtime evidence.",),
            )
        except (OSError, ValueError, TypeError, UnicodeError, InterruptedError) as error:
            completed_at_ns = time.monotonic_ns()
            state = ObservationState.UNVERIFIED if isinstance(error, OSError) else ObservationState.FAILED
            return EvidenceCollection(
                state, source, identity, request, completed_at_ns, None,
                (f"Evidence collection failed closed: {type(error).__name__}: {error}",),
            )
