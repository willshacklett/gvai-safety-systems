"""Standalone, read-only observations of this process; all results are unverified."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
import select
import stat
import sys
import time
from typing import Protocol


MAX_FIELD_BYTES = 64 * 1024
MAX_FD_COUNT = 256
MAX_FD_TARGET_BYTES = 4096
MAX_FDINFO_BYTES = 4096

PROC_SUPER_MAGIC = 0x9FA0
CGROUP2_SUPER_MAGIC = 0x63677270
NSFS_MAGIC = 0x6E736673
NAMESPACE_NAMES = ("cgroup", "ipc", "mnt", "net", "pid", "uts", "user")
NAMESPACE_LINK_PATHS = frozenset(("ns", name) for name in NAMESPACE_NAMES)
FIELD_PATHS = {
    "stat": ("stat",),
    "status": ("status",),
    "uid_map": ("uid_map",),
    "gid_map": ("gid_map",),
    "setgroups": ("setgroups",),
    "cgroup": ("cgroup",),
    "apparmor": ("attr", "current"),
}


@dataclass(frozen=True)
class Observation:
    state: str
    observed_at_monotonic_ns: int
    facts: dict[str, object]
    checks: dict[str, str]
    errors: tuple[str, ...]
    authenticated: bool = False
    runtime_verified: bool = False
    execution_authorized: bool = False
    publication_authorized: bool = False

    def __bool__(self) -> bool:
        return False


class SelfReader(Protocol):
    def process_identity(self) -> dict[str, object]: ...

    def status(self) -> dict[str, object]: ...

    def id_maps(self) -> dict[str, object]: ...

    def apparmor_label(self) -> dict[str, str]: ...

    def namespaces(self) -> dict[str, dict[str, int]]: ...

    def cgroup(self, pid: int) -> dict[str, object]: ...

    def descriptors(self) -> tuple[dict[str, object], ...]: ...


def _filesystem_type(fd: int) -> int:
    import ctypes
    import platform

    if (
        sys.platform != "linux"
        or platform.machine() not in ("x86_64", "aarch64")
        or ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(ctypes.c_long) != 8
    ):
        raise OSError("Unsupported Linux statfs ABI.")

    class StatFS(ctypes.Structure):
        _fields_ = [
            ("f_type", ctypes.c_long), ("f_bsize", ctypes.c_long),
            ("f_blocks", ctypes.c_ulong), ("f_bfree", ctypes.c_ulong),
            ("f_bavail", ctypes.c_ulong), ("f_files", ctypes.c_ulong),
            ("f_ffree", ctypes.c_ulong), ("f_fsid", ctypes.c_int * 2),
            ("f_namelen", ctypes.c_long), ("f_frsize", ctypes.c_long),
            ("f_flags", ctypes.c_long), ("f_spare", ctypes.c_long * 4),
        ]

    call = ctypes.CDLL(None, use_errno=True).fstatfs
    call.argtypes = (ctypes.c_int, ctypes.POINTER(StatFS))
    call.restype = ctypes.c_int
    result = StatFS()
    if call(fd, ctypes.byref(result)) != 0:
        raise OSError(ctypes.get_errno(), "fstatfs failed.")
    return result.f_type


def _read_bounded(fd: int, maximum: int) -> bytes:
    if type(maximum) is not int or not 0 < maximum <= MAX_FIELD_BYTES:
        raise ValueError("Invalid fixed read bound.")
    content = bytearray()
    while len(content) <= maximum:
        chunk = os.read(fd, min(8192, maximum + 1 - len(content)))
        if not chunk:
            break
        content.extend(chunk)
    if len(content) > maximum:
        raise ValueError("Kernel interface exceeded its fixed read bound.")
    return bytes(content)


def _readlink_bounded(directory_fd: int, name: str) -> str:
    import ctypes

    if type(name) is not str or not name.isdecimal():
        raise ValueError("Fixed numeric descriptor name required.")
    library = ctypes.CDLL(None, use_errno=True)
    call = library.readlinkat
    call.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t)
    call.restype = ctypes.c_ssize_t
    buffer = ctypes.create_string_buffer(MAX_FD_TARGET_BYTES + 1)
    result = call(
        directory_fd,
        os.fsencode(name),
        buffer,
        len(buffer),
    )
    if result < 0:
        raise OSError(ctypes.get_errno(), "readlinkat failed.")
    if result > MAX_FD_TARGET_BYTES:
        raise ValueError("FD target exceeds fixed byte limit.")
    return buffer.raw[:result].decode("utf-8", errors="strict")


def _open_beneath(
    directory_fd: int,
    components: tuple[str, ...],
    *,
    follow_final_kernel_link: bool = False,
) -> int:
    if type(components) is not tuple or not components:
        raise ValueError("Fixed relative path components required.")
    if follow_final_kernel_link and components not in NAMESPACE_LINK_PATHS:
        raise ValueError("Only allowlisted namespace links may be followed.")
    current = os.dup(directory_fd)
    try:
        for index, component in enumerate(components):
            if (
                type(component) is not str
                or component in ("", ".", "..")
                or "/" in component
                or "\x00" in component
            ):
                raise ValueError("Unsafe descriptor-relative path component.")
            final = index == len(components) - 1
            flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
            if not (final and follow_final_kernel_link):
                flags |= os.O_NOFOLLOW
            if not final:
                flags |= os.O_DIRECTORY
            next_fd = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        result, current = current, -1
        return result
    finally:
        if current >= 0:
            os.close(current)


def _parse_stat(raw: bytes) -> tuple[int, int]:
    text = raw.decode("ascii", errors="strict").strip()
    left, separator, _ = text.partition(" (")
    right = text.rfind(")")
    if not separator or right <= len(left) + 1 or not left.isdecimal():
        raise ValueError("Malformed self stat record.")
    fields = text[right + 1 :].strip().split()
    if len(fields) <= 19 or not fields[19].isdecimal():
        raise ValueError("Missing self process start time.")
    return int(left), int(fields[19])


def _parse_status(raw: bytes) -> dict[str, object]:
    values: dict[str, str] = {}
    wanted = {
        "Uid", "Gid", "NoNewPrivs", "Seccomp",
        "CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb",
    }
    for line in raw.decode("ascii", errors="strict").splitlines():
        if ":" not in line:
            raise ValueError("Malformed proc status line.")
        key, value = line.split(":", 1)
        key = key.strip()
        if key in wanted:
            if key in values:
                raise ValueError("Duplicate proc status field.")
            values[key] = value.strip()
    try:
        uid = tuple(int(item) for item in values["Uid"].split())
        gid = tuple(int(item) for item in values["Gid"].split())
        nnp = values["NoNewPrivs"]
        seccomp = int(values["Seccomp"])
        capabilities = {
            key: int(values[key], 16)
            for key in ("CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb")
        }
    except (KeyError, ValueError) as error:
        raise ValueError("Incomplete or malformed proc status.") from error
    if (
        len(uid) != 4 or len(gid) != 4
        or any(value < 0 or value >= 1 << 32 for value in (*uid, *gid))
        or nnp not in ("0", "1") or seccomp not in (0, 1, 2)
        or any(value < 0 or value >= 1 << 64 for value in capabilities.values())
    ):
        raise ValueError("Out-of-range process status.")
    return {
        "uid": uid,
        "gid": gid,
        "no_new_privs": nnp == "1",
        "seccomp_mode": seccomp,
        "capabilities": capabilities,
    }


def _parse_map(raw: bytes) -> tuple[tuple[int, int, int], ...]:
    rows = []
    for line in raw.decode("ascii", errors="strict").splitlines():
        values = line.split()
        if len(values) != 3 or any(not value.isdecimal() for value in values):
            raise ValueError("Malformed UID/GID map.")
        inside, outside, length = (int(value) for value in values)
        if (
            length <= 0 or inside + length > 1 << 32
            or outside + length > 1 << 32
        ):
            raise ValueError("Invalid UID/GID mapping range.")
        rows.append((inside, outside, length))
    if not rows:
        raise ValueError("Empty UID/GID map.")
    return tuple(rows)


def _parse_apparmor_label(raw: bytes) -> dict[str, str]:
    value = raw.decode("utf-8", errors="strict").strip()
    if value == "unconfined":
        return {"state": "UNCONFINED", "label": value}
    for suffix, state in ((" (enforce)", "ENFORCING"), (" (complain)", "COMPLAIN")):
        if value.endswith(suffix):
            label = value[: -len(suffix)]
            if (
                not label or label == "unconfined" or len(label) > 4096
                or any(character in label for character in ("\x00", "\n", "\r"))
            ):
                break
            return {"state": state, "label": label}
    raise ValueError("AppArmor label is missing or malformed.")


def _parse_cgroup(raw: bytes) -> str:
    unified = []
    for line in raw.decode("ascii", errors="strict").splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3 or not parts[0].isdecimal():
            raise ValueError("Malformed cgroup membership record.")
        if parts[0] == "0":
            path = parts[2]
            components = path.split("/")
            if (
                parts[1] != "" or not path.startswith("/")
                or (path != "/" and any(not item for item in components[1:]))
                or any(item in (".", "..") for item in components)
                or "\x00" in path
            ):
                raise ValueError("Noncanonical unified cgroup path.")
            unified.append(path)
    if len(unified) != 1:
        raise ValueError("Missing or duplicate cgroup-v2 record.")
    return unified[0]


class LinuxSelfReader:
    """Read fixed interfaces rooted at /proc/self; accepts no target path or PID."""

    def __init__(self) -> None:
        if sys.platform != "linux":
            raise OSError("Linux procfs is unavailable.")
        self._proc_fd = self._self_fd = self._cgroup_fd = self._pidfd = -1
        self._closed = False
        try:
            self._proc_fd = os.open(
                "/proc",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            if _filesystem_type(self._proc_fd) != PROC_SUPER_MAGIC:
                raise OSError("/proc is not procfs.")
            self._self_fd = os.open(
                "self",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
                dir_fd=self._proc_fd,
            )
            if not stat.S_ISDIR(os.fstat(self._self_fd).st_mode):
                raise OSError("/proc/self is not a directory.")
            try:
                sys_fd = os.open(
                    "/sys",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                try:
                    candidate = _open_beneath(sys_fd, ("fs", "cgroup"))
                finally:
                    os.close(sys_fd)
                try:
                    if _filesystem_type(candidate) == CGROUP2_SUPER_MAGIC:
                        self._cgroup_fd = candidate
                        candidate = -1
                finally:
                    if candidate >= 0:
                        os.close(candidate)
            except OSError:
                self._cgroup_fd = -1
            pidfd_open = getattr(os, "pidfd_open", None)
            if pidfd_open is not None:
                try:
                    self._pidfd = pidfd_open(os.getpid(), 0)
                    os.set_inheritable(self._pidfd, False)
                except OSError:
                    self._pidfd = -1
        except BaseException:
            self.close()
            raise

    def _field(self, name: str) -> bytes:
        if self._closed or name not in FIELD_PATHS:
            raise ValueError("Unknown fixed process field or closed reader.")
        fd = _open_beneath(self._self_fd, FIELD_PATHS[name])
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("Proc field is not a regular pseudo-file.")
            return _read_bounded(fd, MAX_FIELD_BYTES)
        finally:
            os.close(fd)

    def _pidfd_status(self) -> str:
        if self._pidfd < 0:
            return "unavailable"
        poller = select.poll()
        poller.register(self._pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            return "exited"
        fd = _open_beneath(self._self_fd, ("fdinfo", str(self._pidfd)))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("pidfd information is not a regular procfs file.")
            raw = _read_bounded(fd, MAX_FDINFO_BYTES).decode("ascii", errors="strict")
        finally:
            os.close(fd)
        pid_values = [
            line.partition(":")[2].strip()
            for line in raw.splitlines()
            if line.startswith("Pid:")
        ]
        if pid_values != [str(os.getpid())]:
            raise ValueError("pidfd does not correlate to this process.")
        return "matched"

    def process_identity(self) -> dict[str, object]:
        first = _parse_stat(self._field("stat"))
        second = _parse_stat(self._field("stat"))
        if first != second or first[0] != os.getpid():
            raise InterruptedError("Self process identity changed.")
        return {"pid": first[0], "start_ticks": first[1], "pidfd": self._pidfd_status()}

    def status(self) -> dict[str, object]:
        first = _parse_status(self._field("status"))
        second = _parse_status(self._field("status"))
        if first != second:
            raise InterruptedError("Self credentials or status changed.")
        return first

    def id_maps(self) -> dict[str, object]:
        result = {
            "uid_map": _parse_map(self._field("uid_map")),
            "gid_map": _parse_map(self._field("gid_map")),
            "setgroups": self._field("setgroups").decode("ascii", errors="strict").strip(),
        }
        if result["setgroups"] not in ("allow", "deny"):
            raise ValueError("Unknown setgroups status.")
        return result

    def apparmor_label(self) -> dict[str, str]:
        values = []
        for _ in range(2):
            values.append(_parse_apparmor_label(self._field("apparmor")))
        if values[0] != values[1]:
            raise InterruptedError("AppArmor label changed.")
        return values[0]

    def namespaces(self) -> dict[str, dict[str, int]]:
        result = {}
        for name in NAMESPACE_NAMES:
            fd = _open_beneath(
                self._self_fd, ("ns", name), follow_final_kernel_link=True,
            )
            try:
                if _filesystem_type(fd) != NSFS_MAGIC:
                    raise OSError("Namespace handle is not nsfs.")
                identity = os.fstat(fd)
                result[name] = {"device": identity.st_dev, "inode": identity.st_ino}
            finally:
                os.close(fd)
        return result

    def cgroup(self, pid: int) -> dict[str, object]:
        if type(pid) is not int or pid != os.getpid():
            raise ValueError("Only this process PID may be observed.")
        if self._cgroup_fd < 0:
            raise OSError("Fixed cgroup-v2 mount is unavailable.")
        raw = self._field("cgroup")
        first_path = _parse_cgroup(raw)
        second_path = _parse_cgroup(self._field("cgroup"))
        if first_path != second_path:
            raise InterruptedError("Self cgroup path changed.")
        parts = first_path.split("/")
        components = tuple(parts[1:]) if first_path != "/" else ()
        directory = os.dup(self._cgroup_fd)
        try:
            if components:
                child = _open_beneath(directory, components)
                os.close(directory)
                directory = child
            identity = os.fstat(directory)
            if _filesystem_type(directory) != CGROUP2_SUPER_MAGIC:
                raise OSError("Resolved cgroup is not cgroup v2.")
            procs = _open_beneath(directory, ("cgroup.procs",))
            try:
                if not stat.S_ISREG(os.fstat(procs).st_mode):
                    raise OSError("cgroup.procs is not a regular pseudo-file.")
                members = _read_bounded(procs, MAX_FIELD_BYTES).decode("ascii").splitlines()
            finally:
                os.close(procs)
            if any(not item.isdecimal() for item in members):
                raise ValueError("Malformed cgroup.procs.")
            return {
                "path_from_proc": first_path,
                "device": identity.st_dev,
                "inode": identity.st_ino,
                "self_pid_listed": str(pid) in members,
            }
        finally:
            os.close(directory)

    def descriptors(self) -> tuple[dict[str, object], ...]:
        fd_dir = _open_beneath(self._self_fd, ("fd",))
        try:
            names = set()
            records = []
            with os.scandir(fd_dir) as entries:
                for entry in entries:
                    name = entry.name
                    if type(name) is not str or not name.isdecimal() or name in names:
                        raise ValueError("Malformed FD inventory.")
                    names.add(name)
                    if len(names) > MAX_FD_COUNT:
                        raise ValueError("FD inventory exceeds fixed count.")
                    target = _readlink_bounded(fd_dir, name)
                    info_fd = _open_beneath(self._self_fd, ("fdinfo", name))
                    try:
                        if not stat.S_ISREG(os.fstat(info_fd).st_mode):
                            raise OSError("FD info is not a regular procfs pseudo-file.")
                        info = _read_bounded(info_fd, MAX_FDINFO_BYTES).decode("ascii", errors="strict")
                    finally:
                        os.close(info_fd)
                    flags = [
                        line.partition(":")[2].strip()
                        for line in info.splitlines()
                        if line.startswith("flags:")
                    ]
                    if len(flags) != 1 or not flags[0] or any(c not in "01234567" for c in flags[0]):
                        raise ValueError("Malformed descriptor flags.")
                    if _readlink_bounded(fd_dir, name) != target:
                        raise InterruptedError("Descriptor was reused during observation.")
                    records.append({"number": int(name), "target": target, "flags_octal": flags[0]})
                return tuple(sorted(records, key=lambda record: record["number"]))
        finally:
            os.close(fd_dir)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        failures = []
        for fd in (self._pidfd, self._self_fd, self._proc_fd, self._cgroup_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError as error:
                    failures.append(error)
        if failures:
            raise failures[0]

    def __enter__(self) -> "LinuxSelfReader":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class SelfObservationHarness:
    """Collects observations; injected readers and reports never grant authority."""

    def collect(self, reader: SelfReader) -> Observation:
        facts: dict[str, object] = {}
        checks: dict[str, str] = {}
        errors = []

        def observe(name: str, callback):
            try:
                value = callback()
                checks[name] = "OBSERVED_UNAUTHENTICATED"
                return value
            except (OSError, ValueError, TypeError, UnicodeError, InterruptedError) as error:
                checks[name] = "UNVERIFIED"
                errors.append(f"{name}: {type(error).__name__}: {error}")
                return None

        def observe_stable(name: str, callback):
            first = observe(name, callback)
            if first is None:
                return None
            second = observe(name, callback)
            if second is None:
                return None
            if first != second:
                checks[name] = "UNVERIFIED"
                errors.append(f"{name}: observations changed between reads.")
                return None
            return first

        def valid(name: str, value: object) -> bool:
            if name == "status":
                keys = {"CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"}
                return (
                    type(value) is dict
                    and type(value.get("uid")) is tuple and len(value["uid"]) == 4
                    and type(value.get("gid")) is tuple and len(value["gid"]) == 4
                    and all(type(item) is int and 0 <= item < 1 << 32
                            for item in (*value["uid"], *value["gid"]))
                    and type(value.get("no_new_privs")) is bool
                    and type(value.get("seccomp_mode")) is int
                    and value["seccomp_mode"] in (0, 1, 2)
                    and type(value.get("capabilities")) is dict
                    and set(value["capabilities"]) == keys
                    and all(type(item) is int and 0 <= item < 1 << 64
                            for item in value["capabilities"].values())
                )
            if name == "uid_gid_maps":
                return (
                    type(value) is dict
                    and type(value.get("setgroups")) is str
                    and value["setgroups"] in ("allow", "deny")
                    and all(
                        type(value.get(field)) is tuple
                        and bool(value[field])
                        and all(
                            type(row) is tuple and len(row) == 3
                            and all(type(item) is int and item >= 0 for item in row)
                            and row[2] > 0
                            and row[0] + row[2] <= 1 << 32
                            and row[1] + row[2] <= 1 << 32
                            for row in value[field]
                        )
                        for field in ("uid_map", "gid_map")
                    )
                )
            if name == "apparmor":
                return (
                    type(value) is dict
                    and set(value) == {"state", "label"}
                    and value["state"] in ("ENFORCING", "UNCONFINED", "COMPLAIN")
                    and type(value["label"]) is str
                    and 0 < len(value["label"]) <= 4096
                    and "\x00" not in value["label"]
                    and (
                        (value["state"] == "UNCONFINED" and value["label"] == "unconfined")
                        or (value["state"] != "UNCONFINED" and value["label"] != "unconfined")
                    )
                )
            if name == "namespaces":
                return (
                    type(value) is dict and set(value) == set(NAMESPACE_NAMES)
                    and all(
                        type(pin) is dict
                        and type(pin.get("device")) is int and pin["device"] >= 0
                        and type(pin.get("inode")) is int and pin["inode"] > 0
                        for pin in value.values()
                    )
                )
            if name == "descriptors":
                return (
                    type(value) is tuple and len(value) <= MAX_FD_COUNT
                    and all(
                        type(record) is dict
                        and type(record.get("number")) is int and record["number"] >= 0
                        and type(record.get("target")) is str
                        and len(record["target"].encode("utf-8", errors="strict")) <= MAX_FD_TARGET_BYTES
                        and type(record.get("flags_octal")) is str
                        and bool(record["flags_octal"])
                        and all(char in "01234567" for char in record["flags_octal"])
                        for record in value
                    )
                    and len({record["number"] for record in value}) == len(value)
                )
            if name == "cgroup_v2":
                return (
                    type(value) is dict
                    and type(value.get("path_from_proc")) is str
                    and len(value["path_from_proc"]) <= MAX_FD_TARGET_BYTES
                    and type(value.get("device")) is int and value["device"] >= 0
                    and type(value.get("inode")) is int and value["inode"] > 0
                    and value.get("self_pid_listed") is True
                )
            return False

        identity = observe_stable("process_identity", reader.process_identity)
        if (
            type(identity) is not dict
            or type(identity.get("pid")) is not int
            or identity["pid"] != os.getpid()
            or type(identity.get("start_ticks")) is not int
            or identity["start_ticks"] < 0
            or identity.get("pidfd") not in ("matched", "unavailable", "exited")
        ):
            identity = None
            checks["process_identity"] = "UNVERIFIED"
            errors.append("process_identity: malformed or non-self process identity.")
        else:
            facts["process_identity"] = identity
            if identity["pidfd"] != "matched":
                checks["pidfd"] = "UNVERIFIED"
                errors.append("pidfd: optional pinned-lifetime support unavailable.")

        for name, callback in (
            ("status", reader.status),
            ("uid_gid_maps", reader.id_maps),
            ("apparmor", reader.apparmor_label),
            ("namespaces", reader.namespaces),
            ("descriptors", reader.descriptors),
        ):
            value = observe_stable(name, callback)
            if value is not None and valid(name, value):
                facts[name] = value
            elif value is not None:
                checks[name] = "UNVERIFIED"
                errors.append(f"{name}: malformed or out-of-bounds observation.")

        if identity is not None:
            cgroup = observe_stable("cgroup_v2", lambda: reader.cgroup(os.getpid()))
            if cgroup is not None and not valid("cgroup_v2", cgroup):
                cgroup = None
                checks["cgroup_v2"] = "UNVERIFIED"
                errors.append("cgroup_v2: missing or invalid self membership.")
            if cgroup is not None:
                facts["cgroup_v2"] = cgroup
        else:
            checks["cgroup_v2"] = "UNVERIFIED"

        if isinstance(reader, LinuxSelfReader) and identity is not None:
            if reader._pidfd_status() != "matched":
                checks["process_identity"] = "UNVERIFIED"
                errors.append("process_identity: pidfd unavailable or process exited.")
                facts.pop("process_identity", None)

        return Observation(
            "UNVERIFIED", time.monotonic_ns(), facts, checks, tuple(errors),
        )


def main() -> int:
    if len(sys.argv) != 1:
        report = Observation(
            "UNVERIFIED", time.monotonic_ns(), {},
            {"arguments": "UNVERIFIED"},
            ("This diagnostic accepts no command-line arguments.",),
        )
    elif sys.platform != "linux":
        report = Observation(
            "UNVERIFIED", time.monotonic_ns(), {},
            {"platform": "UNVERIFIED"},
            ("Linux kernel interfaces are unavailable.",),
        )
    else:
        try:
            with LinuxSelfReader() as reader:
                report = SelfObservationHarness().collect(reader)
        except (OSError, ValueError, TypeError) as error:
            report = Observation(
                "UNVERIFIED", time.monotonic_ns(), {},
                {"reader_setup": "UNVERIFIED"},
                (f"reader_setup: {type(error).__name__}: {error}",),
            )
    print(json.dumps(report.__dict__, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
