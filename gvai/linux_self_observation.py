"""Non-authorizing, read-only observations of this test process only."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import json
import os
import select
import stat
import sys
import time
from typing import Protocol

from gvai.linux_worker_evidence import (
    MAX_FD_COUNT,
    MAX_FD_TARGET_BYTES,
    MAX_FIELD_BYTES,
    ProcessField,
    _filesystem_type,
    _open_components,
    _parse_apparmor_current,
    _parse_cgroup,
    _parse_map,
    _parse_proc_stat,
    _parse_process_status,
    _read_bounded,
)


_PROC_SUPER_MAGIC = 0x9FA0
_CGROUP2_SUPER_MAGIC = 0x63677270
_NSFS_MAGIC = 0x6E736673
_NAMESPACE_NAMES = ("cgroup", "ipc", "mnt", "net", "pid", "uts", "user")
_FIELD_PATHS = {
    ProcessField.STAT: ("stat",),
    ProcessField.STATUS: ("status",),
    ProcessField.UID_MAP: ("uid_map",),
    ProcessField.GID_MAP: ("gid_map",),
    ProcessField.SETGROUPS: ("setgroups",),
    ProcessField.CGROUP: ("cgroup",),
    ProcessField.APPARMOR_CURRENT: ("attr", "current"),
}


class SelfObservationState(Enum):
    UNVERIFIED = "unverified"
    FAILED = "failed"


@dataclass(frozen=True)
class SelfObservation:
    state: SelfObservationState
    observed_at_monotonic_ns: int
    process: dict[str, object] | None
    namespaces: dict[str, tuple[int, int]] | None
    cgroup: dict[str, object] | None
    descriptors: tuple[dict[str, object], ...] | None
    checks: dict[str, str]
    errors: tuple[str, ...]
    authenticated: bool = False
    runtime_verified: bool = False
    execution_authorized: bool = False
    publication_authorized: bool = False

    def __bool__(self) -> bool:
        return False


class SelfObservationReader(Protocol):
    def process_identity(self) -> tuple[int, int, str]: ...

    def process_status(self) -> tuple[object, ...]: ...

    def id_maps(self) -> tuple[tuple[tuple[int, int, int], ...], tuple[tuple[int, int, int], ...], str]: ...

    def apparmor_label(self) -> str: ...

    def namespace_identities(self) -> dict[str, tuple[int, int]]: ...

    def cgroup_observation(self, pid: int) -> dict[str, object]: ...

    def descriptor_inventory(self) -> tuple[dict[str, object], ...]: ...

    def pidfd_status(self, pid: int) -> str: ...


class LinuxSelfObservationReader:
    """Reader anchored to this process' procfs entry; accepts no target PID."""

    def __init__(self) -> None:
        if sys.platform != "linux":
            raise OSError("Linux procfs observation is unavailable.")
        self._proc_fd = self._self_fd = self._pidfd = self._cgroup_fd = -1
        self._closed = False
        try:
            self._proc_fd = os.open(
                "/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            if _filesystem_type(self._proc_fd) != _PROC_SUPER_MAGIC:
                raise OSError("/proc is not procfs.")
            self._self_fd = _open_components(self._proc_fd, ("self",), follow_final=True)
            if not stat.S_ISDIR(os.fstat(self._self_fd).st_mode):
                raise OSError("/proc/self is not a directory.")
            try:
                self._cgroup_fd = os.open(
                    "/sys/fs/cgroup",
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                )
                if _filesystem_type(self._cgroup_fd) != _CGROUP2_SUPER_MAGIC:
                    os.close(self._cgroup_fd)
                    self._cgroup_fd = -1
            except OSError:
                self._cgroup_fd = -1
            pid = os.getpid()
            pidfd_open = getattr(os, "pidfd_open", None)
            if pidfd_open is not None:
                try:
                    self._pidfd = pidfd_open(pid, 0)
                    os.set_inheritable(self._pidfd, False)
                except OSError:
                    self._pidfd = -1
        except BaseException:
            self.close()
            raise

    def _read_field(self, field: ProcessField) -> bytes:
        if self._closed:
            raise ValueError("Reader is closed.")
        fd = _open_components(self._self_fd, _FIELD_PATHS[field])
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError("Process observation is not a regular procfs pseudo-file.")
            return _read_bounded(fd, MAX_FIELD_BYTES)
        finally:
            os.close(fd)

    def process_identity(self) -> tuple[int, int, str]:
        pid = os.getpid()
        first = _parse_proc_stat(self._read_field(ProcessField.STAT))
        second = _parse_proc_stat(self._read_field(ProcessField.STAT))
        if first != second or first[0] != pid:
            raise InterruptedError("Self process identity changed during observation.")
        pidfd_status = self.pidfd_status(pid)
        if pidfd_status == "matched":
            raw_fdinfo = os.open(
                f"/proc/self/fdinfo/{self._pidfd}",
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
            )
            try:
                from gvai.linux_worker_evidence import _parse_key_values

                pid_value = _parse_key_values(_read_bounded(raw_fdinfo, 4096), {"Pid"}).get("Pid")
            finally:
                os.close(raw_fdinfo)
            if pid_value != str(pid):
                raise ValueError("pidfd does not correlate to this process.")
        return first[0], first[1], pidfd_status

    def process_status(self) -> tuple[object, ...]:
        first = _parse_process_status(self._read_field(ProcessField.STATUS))
        second = _parse_process_status(self._read_field(ProcessField.STATUS))
        if first != second:
            raise InterruptedError("Process credentials or security state changed.")
        return first

    def id_maps(self) -> tuple[
        tuple[tuple[int, int, int], ...],
        tuple[tuple[int, int, int], ...],
        str,
    ]:
        uid_map = _parse_map(self._read_field(ProcessField.UID_MAP))
        gid_map = _parse_map(self._read_field(ProcessField.GID_MAP))
        setgroups = self._read_field(ProcessField.SETGROUPS).decode("ascii").strip()
        if setgroups not in ("allow", "deny"):
            raise ValueError("Unknown setgroups value.")
        return uid_map, gid_map, setgroups

    def apparmor_label(self) -> str:
        first = _parse_apparmor_current(self._read_field(ProcessField.APPARMOR_CURRENT))
        second = _parse_apparmor_current(self._read_field(ProcessField.APPARMOR_CURRENT))
        if first != second:
            raise InterruptedError("AppArmor label changed during observation.")
        return first

    def namespace_identities(self) -> dict[str, tuple[int, int]]:
        result = {}
        for name in _NAMESPACE_NAMES:
            fd = _open_components(self._self_fd, ("ns", name), follow_final=True)
            try:
                if _filesystem_type(fd) != _NSFS_MAGIC:
                    raise OSError(f"{name} namespace descriptor is not nsfs.")
                facts = os.fstat(fd)
                result[name] = (facts.st_dev, facts.st_ino)
            finally:
                os.close(fd)
        return result

    def cgroup_observation(self, pid: int) -> dict[str, object]:
        if self._cgroup_fd < 0:
            raise OSError("Fixed cgroup-v2 mount is unavailable.")
        raw = self._read_field(ProcessField.CGROUP)
        path = _parse_cgroup(raw)
        parts = path.split("/")
        if path != "/" and (len(parts) < 2 or any(not part for part in parts[1:])):
            raise ValueError("Noncanonical kernel-reported cgroup path.")
        components = tuple(part for part in parts if part)
        if any(part in (".", "..") or "/" in part for part in components):
            raise ValueError("Unsafe kernel-reported cgroup path.")
        cgroup_fd = os.dup(self._cgroup_fd)
        try:
            if components:
                descendant = _open_components(cgroup_fd, components)
                os.close(cgroup_fd)
                cgroup_fd = descendant
            facts = os.fstat(cgroup_fd)
            if _filesystem_type(cgroup_fd) != _CGROUP2_SUPER_MAGIC:
                raise OSError("Resolved process cgroup is not cgroup v2.")
            procs_fd = _open_components(cgroup_fd, ("cgroup.procs",))
            try:
                raw_procs = _read_bounded(procs_fd, MAX_FIELD_BYTES)
            finally:
                os.close(procs_fd)
            members = raw_procs.decode("ascii", errors="strict").splitlines()
            if any(not member.isdecimal() for member in members):
                raise ValueError("Malformed cgroup.procs inventory.")
            return {
                "path_from_proc": path,
                "device": facts.st_dev,
                "inode": facts.st_ino,
                "self_pid_listed": str(pid) in members,
            }
        finally:
            os.close(cgroup_fd)

    def descriptor_inventory(self) -> tuple[dict[str, object], ...]:
        fd_dir = _open_components(self._self_fd, ("fd",))
        try:
            names = []
            with os.scandir(fd_dir) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if len(names) > MAX_FD_COUNT:
                        raise ValueError("Descriptor inventory exceeds fixed bound.")
            if any(not name.isdecimal() for name in names) or len(set(names)) != len(names):
                raise ValueError("Malformed descriptor inventory.")
            records = []
            for name in sorted(names, key=int):
                target = os.readlink(name, dir_fd=fd_dir)
                if len(target.encode("utf-8", errors="strict")) > MAX_FD_TARGET_BYTES:
                    raise ValueError("Descriptor target exceeds fixed bound.")
                info_fd = _open_components(self._self_fd, ("fdinfo", name))
                try:
                    raw_info = _read_bounded(info_fd, 4096).decode("ascii", errors="strict")
                finally:
                    os.close(info_fd)
                flags = None
                for line in raw_info.splitlines():
                    if line.startswith("flags:"):
                        flags = line.partition(":")[2].strip()
                        break
                if flags is None or not flags or not all(char in "01234567" for char in flags):
                    raise ValueError("Descriptor flags are unavailable or malformed.")
                records.append({"number": int(name), "target": target, "flags_octal": flags})
            return tuple(records)
        finally:
            os.close(fd_dir)

    def pidfd_status(self, pid: int) -> str:
        if type(pid) is not int or pid != os.getpid():
            raise ValueError("The reader can observe only its own process.")
        if self._pidfd < 0:
            return "unavailable"
        poller = select.poll()
        poller.register(self._pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        return "matched" if not poller.poll(0) else "exited"

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        errors = []
        for fd in (self._pidfd, self._self_fd, self._proc_fd, self._cgroup_fd):
            if fd < 0:
                continue
            try:
                os.close(fd)
            except OSError as error:
                errors.append(error)
        if errors:
            raise errors[0]

    def __enter__(self) -> "LinuxSelfObservationReader":
        if self._closed:
            raise ValueError("Reader is closed.")
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class SelfObservationHarness:
    """Collect observations without assigning identity or granting authority."""

    def collect(self, reader: SelfObservationReader) -> SelfObservation:
        checks: dict[str, str] = {}
        errors: list[str] = []
        process = namespaces = cgroup = descriptors = None
        observed_at_ns = time.monotonic_ns()

        def check(name: str, callback):
            try:
                value = callback()
                checks[name] = "OBSERVED_UNAUTHENTICATED"
                return value
            except (OSError, ValueError, TypeError, UnicodeError, InterruptedError) as error:
                checks[name] = "UNVERIFIED"
                errors.append(f"{name}: {type(error).__name__}: {error}")
                return None

        def check_stable(name: str, callback):
            first = check(name, callback)
            if first is None:
                return None
            second = check(name, callback)
            if second is None:
                return None
            if first != second:
                checks[name] = "UNVERIFIED"
                errors.append(f"{name}: observations changed between bounded reads.")
                return None
            return first

        identity = check("process_identity", reader.process_identity)
        if identity is not None:
            if (
                type(identity) is not tuple or len(identity) != 3
                or type(identity[0]) is not int or identity[0] <= 0
                or identity[0] != os.getpid()
                or type(identity[1]) is not int or identity[1] < 0
                or identity[2] not in ("matched", "unavailable", "exited")
            ):
                checks["process_identity"] = "UNVERIFIED"
                errors.append("process_identity: reader returned malformed identity.")
                identity = None
            else:
                pid, start_ticks, pidfd_status = identity
                process = {"pid": pid, "start_ticks": start_ticks, "pidfd": pidfd_status}
                if pidfd_status != "matched":
                    checks["pidfd"] = "UNVERIFIED"
                    errors.append("pidfd: support or live-process correlation unavailable.")
        status = check_stable("credentials_capabilities_nnp_seccomp", reader.process_status)
        if status is not None:
            uid, gid, nnp, seccomp, capabilities = status
            process = process or {}
            process.update({
                "uid": uid,
                "gid": gid,
                "no_new_privs": nnp,
                "seccomp_mode": seccomp,
                "capabilities": capabilities,
            })
        maps = check_stable("uid_gid_maps", reader.id_maps)
        if maps is not None:
            process = process or {}
            process.update({"uid_map": maps[0], "gid_map": maps[1], "setgroups": maps[2]})
        label = check("apparmor_label", reader.apparmor_label)
        if label is not None:
            process = process or {}
            process["apparmor_label"] = label
        namespaces = check_stable("namespaces", reader.namespace_identities)
        if identity is not None:
            cgroup = check_stable(
                "cgroup_v2_membership",
                lambda: reader.cgroup_observation(identity[0]),
            )
            if cgroup is not None and (
                type(cgroup) is not dict
                or type(cgroup.get("device")) is not int
                or type(cgroup.get("inode")) is not int
                or type(cgroup.get("self_pid_listed")) is not bool
                or cgroup.get("self_pid_listed") is not True
            ):
                checks["cgroup_v2_membership"] = "UNVERIFIED"
                errors.append("cgroup_v2_membership: malformed or absent self membership.")
                cgroup = None
        else:
            checks["cgroup_v2_membership"] = "UNVERIFIED"
        descriptors = check_stable("descriptor_inventory", reader.descriptor_inventory)
        if identity is not None:
            final_pidfd = check("pidfd_final_liveness", lambda: reader.pidfd_status(identity[0]))
            if final_pidfd != "matched":
                errors.append("process_identity: self pidfd is unavailable or reports exit.")
                checks["process_identity"] = "UNVERIFIED"
                process = None
        completed_at_ns = time.monotonic_ns()
        if completed_at_ns < observed_at_ns:
            errors.append("clock: monotonic clock reversed.")
        if any(value == "UNVERIFIED" for value in checks.values()):
            errors.append("One or more kernel interfaces were unavailable or inconclusive.")
        return SelfObservation(
            SelfObservationState.UNVERIFIED, completed_at_ns, process,
            namespaces, cgroup, descriptors, checks, tuple(errors),
        )


def main() -> int:
    if len(sys.argv) != 1:
        observation = SelfObservation(
            SelfObservationState.UNVERIFIED, time.monotonic_ns(), None, None,
            None, None, {"arguments": "UNVERIFIED"},
            ("This observation module accepts no command-line arguments.",),
        )
    elif sys.platform != "linux":
        observation = SelfObservation(
            SelfObservationState.UNVERIFIED, time.monotonic_ns(), None, None,
            None, None, {"platform": "UNVERIFIED"},
            ("Linux kernel interfaces are unavailable.",),
        )
    else:
        try:
            with LinuxSelfObservationReader() as reader:
                observation = SelfObservationHarness().collect(reader)
        except (OSError, ValueError, TypeError) as error:
            observation = SelfObservation(
                SelfObservationState.UNVERIFIED, time.monotonic_ns(), None,
                None, None, None, {"reader_setup": "UNVERIFIED"},
                (f"reader_setup: {type(error).__name__}: {error}",),
            )
    print(json.dumps(observation.__dict__, default=lambda value: value.value, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
