"""Read-only Linux host observations; never grants runtime or launch authority."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import time
from typing import Protocol, runtime_checkable

from gvai.systemd_worker_profile import (
    REQUIRED_CGROUP_CONTROLLERS,
    REQUIRED_NAMESPACES,
    RUNTIME_MOUNTS,
    SYSTEMD_255_PROPERTIES,
    WORKER_APPARMOR_PROFILE,
    WORKER_SECCOMP_POLICY_ID,
)

MAX_OBSERVATION_BYTES = 128 * 1024
VERSION_TIMEOUT_SECONDS = 2.0
VERSION_EXECUTABLES = {
    "systemd": "/usr/lib/systemd/systemd",
    "bubblewrap": "/usr/bin/bwrap",
}
NAMESPACE_PATHS = {
    name: f"/proc/self/ns/{name}"
    for name in sorted(REQUIRED_NAMESPACES)
}
RUNTIME_MOUNTINFO = "/proc/self/mountinfo"
CGROUP_ROOT = "/sys/fs/cgroup"
CGROUP_CONTROLLERS = f"{CGROUP_ROOT}/cgroup.controllers"
APPARMOR_PROFILES = "/sys/kernel/security/apparmor/profiles"
SECCOMP_ACTIONS = "/proc/sys/kernel/seccomp/actions_avail"
PROCESS_STATUS = "/proc/self/status"
WORKER_ID_CONFIG = "/etc/gvai/worker-id-range"
SECCOMP_POLICY_ID_PATH = "/etc/gvai/seccomp/worker-policy-id"
SCRATCH_ROOT = "/var/lib/gvai/scratch"
MANAGER_SOCKET = "/run/systemd/private"
CONTROL_PATHS = (MANAGER_SOCKET, "/run/dbus/system_bus_socket")

_ISSUER = object()


class EvidenceSource(Enum):
    KERNEL_INTERFACE = "kernel-interface"
    CONFIGURATION_ASSUMPTION = "configuration-assumption"
    EXECUTABLE_QUERY = "fixed-executable-version-query"
    INJECTED_TEST_READER = "injected-test-reader"


class CheckState(Enum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    FAILED = "failed"


@dataclass(frozen=True)
class FileFacts:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True)
class RawObservation:
    check: str
    source: EvidenceSource
    value: str | None
    error: str | None = None
    _issuer: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._issuer is not _ISSUER:
            raise ValueError("Raw observations must be issued by the host collector.")


@dataclass(frozen=True)
class ValidatedEvidence:
    check: str
    state: CheckState
    source: EvidenceSource
    detail: str
    _issuer: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._issuer is not _ISSUER:
            raise ValueError("Validated evidence must be issued by the host validator.")


@dataclass(frozen=True)
class HostPreflightReport:
    raw_observations: tuple[RawObservation, ...]
    validated_evidence: tuple[ValidatedEvidence, ...]
    unverified_requirements: tuple[str, ...]
    failures: tuple[str, ...]
    collected_at_monotonic_ns: int
    observations_from_trusted_local_reader: bool
    _issuer: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._issuer is not _ISSUER:
            raise ValueError("Preflight reports must be issued by the host collector.")

    @property
    def ready_to_run(self) -> bool:
        return False

    @property
    def execution_authorized(self) -> bool:
        return False

    @property
    def output_publication_authorized(self) -> bool:
        return False

    @property
    def all_requirements_verified(self) -> bool:
        return False

    @property
    def trusted_worker_capabilities(self) -> None:
        return None

    def is_stale(self, max_age_seconds: int, now_monotonic_ns: int | None = None) -> bool:
        if type(max_age_seconds) is not int or max_age_seconds <= 0:
            raise ValueError("A positive maximum evidence age is required.")
        now = time.monotonic_ns() if now_monotonic_ns is None else now_monotonic_ns
        if type(now) is not int:
            raise ValueError("Monotonic timestamp must be an integer.")
        return now < self.collected_at_monotonic_ns or (
            now - self.collected_at_monotonic_ns > max_age_seconds * 1_000_000_000
        )


@runtime_checkable
class HostReader(Protocol):
    """Narrow observation interface; its implementation is part of the TCB."""

    def read_text(self, path: str, max_bytes: int) -> str: ...

    def file_facts(self, path: str) -> FileFacts: ...

    def version_output(self, name: str) -> str: ...


class LinuxHostReader:
    """Fixed-path, bounded, read-only local host reader.

    Version queries invoke only fixed binaries with ``--version``; they never
    invoke systemctl, D-Bus, a service, Bubblewrap sandbox mode, or a worker.
    """

    def read_text(self, path: str, max_bytes: int) -> str:
        if (
            path not in _ALLOWED_TEXT_PATHS or type(max_bytes) is not int
            or not 0 < max_bytes <= MAX_OBSERVATION_BYTES
        ):
            raise ValueError("Unapproved host observation path or size.")
        descriptor = self._open_fixed(
            path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0),
        )
        try:
            facts = os.fstat(descriptor)
            if not stat.S_ISREG(facts.st_mode):
                raise OSError("Observation target is not a regular pseudo-file.")
            chunks = bytearray()
            while len(chunks) <= max_bytes:
                chunk = os.read(descriptor, min(16 * 1024, max_bytes + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            content = bytes(chunks)
        finally:
            os.close(descriptor)
        if len(content) > max_bytes:
            raise ValueError("Host observation exceeded its fixed size limit.")
        return content.decode("utf-8", errors="strict")

    def file_facts(self, path: str) -> FileFacts:
        if path not in _ALLOWED_STAT_PATHS:
            raise ValueError("Unapproved host stat path.")
        parent_fd, name = self._open_parent(path)
        try:
            facts = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        finally:
            os.close(parent_fd)
        return FileFacts(facts.st_dev, facts.st_ino, facts.st_mode, facts.st_uid, facts.st_gid)

    def version_output(self, name: str) -> str:
        executable = VERSION_EXECUTABLES.get(name)
        if executable is None:
            raise ValueError("Unapproved version query.")
        descriptor = self._open_fixed(
            executable, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0),
        )
        try:
            facts = os.fstat(descriptor)
            if not stat.S_ISREG(facts.st_mode) or not facts.st_mode & 0o111:
                raise OSError("Version-query executable is not a regular executable.")
            process = subprocess.Popen(
                [f"/proc/self/fd/{descriptor}", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
                cwd="/",
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                close_fds=True,
                pass_fds=(descriptor,),
            )
            output = bytearray()
            deadline = time.monotonic() + VERSION_TIMEOUT_SECONDS
            with selectors.DefaultSelector() as selector:
                if process.stdout is None:
                    raise OSError("Version query did not provide a bounded output stream.")
                os.set_blocking(process.stdout.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise TimeoutError("Fixed version query timed out.")
                    chunk = os.read(process.stdout.fileno(), 4097 - len(output))
                    if not chunk:
                        selector.unregister(process.stdout)
                        continue
                    output.extend(chunk)
                    if len(output) > 4096:
                        raise ValueError("Version output exceeded its fixed size limit.")
            if process.wait(timeout=max(0.0, deadline - time.monotonic())) != 0:
                raise OSError("Fixed version query failed.")
            return output.decode("utf-8", errors="strict")
        finally:
            if "process" in locals() and process.poll() is None:
                process.kill()
                process.wait()
            if "process" in locals() and process.stdout is not None:
                process.stdout.close()
            os.close(descriptor)

    @staticmethod
    def _open_fixed(path: str, final_flags: int) -> int:
        parent_fd, name = LinuxHostReader._open_parent(path)
        try:
            flags = (
                final_flags | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            return os.open(name, flags, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)

    @staticmethod
    def _open_parent(path: str) -> tuple[int, str]:
        if (
            type(path) is not str or not path.startswith("/")
            or any(part in ("", ".", "..") for part in path.split("/")[1:-1])
        ):
            raise ValueError("Host path is not canonical and absolute.")
        parts = path.split("/")[1:]
        if not parts or not parts[-1]:
            raise ValueError("Host path must name a file or directory.")
        directory_flags = (
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        current_fd = os.open("/", directory_flags)
        try:
            for component in parts[:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=current_fd)
                os.close(current_fd)
                current_fd = next_fd
            return current_fd, parts[-1]
        except BaseException:
            os.close(current_fd)
            raise


_ALLOWED_TEXT_PATHS = frozenset({
    "/proc/sys/kernel/osrelease",
    RUNTIME_MOUNTINFO,
    CGROUP_CONTROLLERS,
    APPARMOR_PROFILES,
    SECCOMP_ACTIONS,
    PROCESS_STATUS,
    WORKER_ID_CONFIG,
    SECCOMP_POLICY_ID_PATH,
})
_ALLOWED_STAT_PATHS = frozenset({
    CGROUP_ROOT,
    *(NAMESPACE_PATHS.values()),
    *(RUNTIME_MOUNTS),
    SCRATCH_ROOT,
    *(CONTROL_PATHS),
    *(VERSION_EXECUTABLES.values()),
})


def _make_raw(
    check: str,
    source: EvidenceSource,
    reader_call,
) -> RawObservation:
    try:
        value = reader_call()
        if type(value) is not str:
            raise ValueError("Observation reader returned a non-text value.")
        return RawObservation(check, source, value, _issuer=_ISSUER)
    except (OSError, UnicodeError, ValueError, TimeoutError, subprocess.SubprocessError) as error:
        return RawObservation(
            check, source, None, type(error).__name__, _issuer=_ISSUER,
        )


def _validate(
    raw: RawObservation,
    predicate,
    detail: str,
) -> ValidatedEvidence:
    if raw.value is None:
        return ValidatedEvidence(
            raw.check, CheckState.UNVERIFIED, raw.source,
            f"Observation unavailable ({raw.error}).", _issuer=_ISSUER,
        )
    try:
        valid = predicate(raw.value)
    except (ValueError, TypeError, IndexError):
        valid = False
    state = CheckState.VERIFIED if valid else CheckState.FAILED
    return ValidatedEvidence(
        raw.check, state, raw.source,
        detail if valid else "Observation malformed, contradictory, or outside the allowlist.",
        _issuer=_ISSUER,
    )


def _read_text(reader: HostReader, path: str) -> str:
    return reader.read_text(path, MAX_OBSERVATION_BYTES)


def _parse_kernel_release(value: str) -> bool:
    return re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+._A-Za-z0-9]*)?", value.strip()) is not None


def _parse_version(value: str, component: str) -> bool:
    first = value.strip().splitlines()[0] if value.strip() else ""
    match = re.search(rf"(?<![A-Za-z]){re.escape(component)}\s+([0-9]+)(?:\.([0-9]+))?", first)
    if not match:
        return False
    major = int(match.group(1))
    return major == 255 if component == "systemd" else True


def _mountinfo_has_cgroup2(value: str) -> bool:
    matches = _cgroup_mount_records(value)
    return len(matches) == 1 and matches[0][1] == "cgroup2"


def _cgroup_mount_records(value: str) -> list[tuple[tuple[int, int] | None, str]]:
    matches = []
    for line in value.splitlines():
        if " - " not in line:
            continue
        left, right = line.split(" - ", 1)
        left_fields = left.split()
        right_fields = right.split()
        if len(left_fields) < 5 or len(right_fields) < 3:
            continue
        if left_fields[4].replace("\\040", " ") != CGROUP_ROOT:
            continue
        device = left_fields[2].split(":")
        parsed_device = (
            (int(device[0]), int(device[1]))
            if len(device) == 2 and all(part.isdecimal() for part in device)
            else None
        )
        matches.append((parsed_device, right_fields[0]))
    return matches


def _has_controllers(value: str) -> bool:
    items = value.split()
    return len(items) == len(set(items)) and REQUIRED_CGROUP_CONTROLLERS <= set(items)


def _profile_enforcing(value: str) -> bool:
    matches = [
        line.strip() for line in value.splitlines()
        if line.strip().startswith(f"{WORKER_APPARMOR_PROFILE} ")
    ]
    return matches == [f"{WORKER_APPARMOR_PROFILE} (enforce)"]


def _seccomp_available(value: str) -> bool:
    return "kill_process" in value.split() and "errno" in value.split()


def _parse_status_fields(value: str) -> bool:
    fields = {}
    for line in value.splitlines():
        if ":" not in line:
            continue
        name, content = line.split(":", 1)
        if name in fields:
            return False
        fields[name] = content
    if not {"NoNewPrivs", "CapEff"} <= fields.keys():
        return False
    try:
        no_new_privs = int(fields["NoNewPrivs"].strip())
        effective_caps = int(fields["CapEff"].strip(), 16)
    except ValueError:
        return False
    return no_new_privs in (0, 1) and effective_caps >= 0


def _policy_id_matches(value: str) -> bool:
    return value.strip() == WORKER_SECCOMP_POLICY_ID


def _parse_uid_gid_range(value: str) -> bool:
    fields = {}
    for line in value.splitlines():
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            return False
        key, raw = line.split("=", 1)
        if key not in {"uid_min", "uid_max", "gid_min", "gid_max"} or key in fields:
            return False
        if not raw.isdecimal():
            return False
        fields[key] = int(raw)
    return (
        set(fields) == {"uid_min", "uid_max", "gid_min", "gid_max"}
        and fields["uid_min"] > 0 and fields["gid_min"] > 0
        and fields["uid_min"] <= fields["uid_max"]
        and fields["gid_min"] <= fields["gid_max"]
    )


def _file_facts_observation(reader: HostReader, path: str) -> str:
    facts = reader.file_facts(path)
    if type(facts) is not FileFacts or any(type(value) is not int for value in (
        facts.device, facts.inode, facts.mode, facts.uid, facts.gid,
    )):
        raise ValueError("Malformed file identity observation.")
    return f"{facts.device}:{facts.inode}:{facts.mode:o}:{facts.uid}:{facts.gid}"


def _identity_shape(value: str) -> bool:
    fields = value.split(":")
    return (
        len(fields) == 5
        and all(re.fullmatch(r"[0-9]+", field) is not None for field in fields)
        and int(fields[1]) > 0
        and stat.S_ISDIR(int(fields[2], 8))
    )


def _executable_identity(value: str) -> bool:
    fields = value.split(":")
    return (
        len(fields) == 5
        and all(re.fullmatch(r"[0-9]+", field) is not None for field in fields)
        and int(fields[1]) > 0
        and stat.S_ISREG(int(fields[2], 8))
        and bool(int(fields[2], 8) & 0o111)
    )


def collect_linux_host_preflight(
    reader: HostReader | None = None,
) -> HostPreflightReport:
    """Collect allowlisted observations and validate only their narrow meaning.

    A successful observation never proves worker isolation, a trusted policy
    installation, manager separation, or readiness to launch.
    """

    active_reader = LinuxHostReader() if reader is None else reader
    if not isinstance(active_reader, HostReader):
        raise TypeError("Host reader must implement the fixed observation interface.")
    injected_reader = reader is not None
    collected_at = time.monotonic_ns()
    raw_records: list[RawObservation] = []
    evidence: list[ValidatedEvidence] = []

    def text(check: str, path: str, source: EvidenceSource, predicate, detail: str) -> RawObservation:
        if injected_reader:
            source = EvidenceSource.INJECTED_TEST_READER
        raw = _make_raw(check, source, lambda: _read_text(active_reader, path))
        raw_records.append(raw)
        evidence.append(_validate(raw, predicate, detail))
        return raw

    def version(check: str, tool: str, component: str) -> None:
        source = (
            EvidenceSource.INJECTED_TEST_READER if injected_reader
            else EvidenceSource.EXECUTABLE_QUERY
        )
        raw = _make_raw(
            check, source,
            lambda: active_reader.version_output(tool),
        )
        raw_records.append(raw)
        evidence.append(_validate(
            raw, lambda value: _parse_version(value, component),
            f"Observed fixed {component} version output; executable provenance is not pinned.",
        ))

    def facts(check: str, path: str, predicate, detail: str) -> RawObservation:
        source = (
            EvidenceSource.INJECTED_TEST_READER if injected_reader
            else EvidenceSource.KERNEL_INTERFACE
        )
        raw = _make_raw(
            check, source,
            lambda: _file_facts_observation(active_reader, path),
        )
        raw_records.append(raw)
        evidence.append(_validate(raw, predicate, detail))
        return raw

    text(
        "kernel-version", "/proc/sys/kernel/osrelease",
        EvidenceSource.KERNEL_INTERFACE, _parse_kernel_release,
        "Kernel release string is syntactically valid; required features remain unverified.",
    )
    version("systemd-version", "systemd", "systemd")
    version("bubblewrap-version", "bubblewrap", "bubblewrap")

    cgroup_mount = text(
        "cgroup2-mount", RUNTIME_MOUNTINFO, EvidenceSource.KERNEL_INTERFACE,
        _mountinfo_has_cgroup2, "Kernel mount table reports cgroup2 at the fixed hierarchy path.",
    )
    text(
        "cgroup2-controllers", CGROUP_CONTROLLERS, EvidenceSource.KERNEL_INTERFACE,
        _has_controllers, "Required controller names are present; delegation and enforcement remain unverified.",
    )
    cgroup_identity = facts(
        "cgroup-root-identity", CGROUP_ROOT, _identity_shape,
        "Cgroup root has a directory identity; mount identity is separately checked.",
    )
    identity_matches = False
    if cgroup_mount.value is not None and cgroup_identity.value is not None:
        mount_records = _cgroup_mount_records(cgroup_mount.value)
        mount_device = (
            mount_records[0][0]
            if len(mount_records) == 1 and mount_records[0][1] == "cgroup2"
            else None
        )
        identity_device = int(cgroup_identity.value.split(":", 1)[0])
        identity_matches = (
            mount_device is not None
            and (os.major(identity_device), os.minor(identity_device)) == mount_device
        )
    evidence.append(ValidatedEvidence(
        "cgroup2-filesystem-identity",
        CheckState.VERIFIED if identity_matches else (
            CheckState.UNVERIFIED
            if cgroup_mount.value is None or cgroup_identity.value is None
            else CheckState.FAILED
        ),
        EvidenceSource.INJECTED_TEST_READER if injected_reader else EvidenceSource.KERNEL_INTERFACE,
        "Mountinfo device identity matches the cgroup root stat identity."
        if identity_matches else "Cgroup mount and directory filesystem identities are missing or contradictory.",
        _issuer=_ISSUER,
    ))

    for namespace, path in NAMESPACE_PATHS.items():
        facts(
            f"namespace-handle-{namespace}", path,
            lambda value: len(value.split(":")) == 5 and int(value.split(":")[1]) > 0,
            f"Current process namespace handle {namespace} is observable; creation support remains unverified.",
        )

    text(
        "apparmor-profile", APPARMOR_PROFILES, EvidenceSource.KERNEL_INTERFACE,
        _profile_enforcing, "Fixed worker AppArmor profile is listed in enforce mode.",
    )
    text(
        "seccomp-actions", SECCOMP_ACTIONS, EvidenceSource.KERNEL_INTERFACE,
        _seccomp_available, "Kernel advertises seccomp action names; filter behavior remains unverified.",
    )
    text(
        "process-privilege-observation", PROCESS_STATUS, EvidenceSource.KERNEL_INTERFACE,
        _parse_status_fields, "Collector process status parsed; worker no-new-privileges and capabilities remain unverified.",
    )
    facts(
        "bubblewrap-file-identity", VERSION_EXECUTABLES["bubblewrap"],
        _executable_identity,
        "Bubblewrap executable metadata observed; binary trust and version provenance remain unverified.",
    )
    for mount in RUNTIME_MOUNTS:
        facts(
            f"runtime-path-{mount}", mount,
            lambda value: _identity_shape(value),
            "Runtime path identity observed; mount read-only status and symlink-safe pinning remain unverified.",
        )
    facts(
        "scratch-root", SCRATCH_ROOT,
        lambda value: _identity_shape(value),
        "Scratch root identity observed; tmpfs backing, quota, and privacy remain unverified.",
    )
    text(
        "seccomp-policy-id-configuration", SECCOMP_POLICY_ID_PATH,
        EvidenceSource.CONFIGURATION_ASSUMPTION, _policy_id_matches,
        "Configuration names the fixed seccomp policy; authenticity and installed-filter proof remain unverified.",
    )
    text(
        "worker-id-range-configuration", WORKER_ID_CONFIG,
        EvidenceSource.CONFIGURATION_ASSUMPTION, _parse_uid_gid_range,
        "Worker UID/GID range syntax is valid; allocation ownership and uniqueness remain unverified.",
    )
    for control_path in CONTROL_PATHS:
        facts(
            f"control-path-{control_path}", control_path,
            lambda value: len(value.split(":")) == 5 and int(value.split(":")[1]) > 0,
            "Control path presence observed; worker reachability and manager separation remain unverified.",
        )

    # These are deliberately configuration/runtime obligations, not booleans
    # inferred from the collector process or an arbitrary caller mapping.
    assumptions = (
        ("systemd-255-property-compatibility", "Static allowlisting is not host-side property verification."),
        ("worker-uid-gid-allocation", f"Trusted allocation source {WORKER_ID_CONFIG} is not authenticated or configured."),
        ("approved-seccomp-policy", f"Policy identity {WORKER_SECCOMP_POLICY_ID} has no pinned trusted digest or installed-filter proof."),
        ("seccomp-policy-installation", "A policy identifier is configuration, not proof of verified descriptor provenance or installation."),
        ("namespace-creation-support", f"Namespace handles exist for {', '.join(sorted(REQUIRED_NAMESPACES))}; creating required namespaces is unverified."),
        ("apparmor-enforcement-on-worker", "Profile presence does not prove worker attachment or effective enforcement."),
        ("worker-no-new-privileges-and-capabilities", "Current collector credentials do not prove worker credentials."),
        ("manager-separation", "No static filesystem observation proves manager/worker process separation."),
        ("control-path-nonexposure", "Filesystem metadata does not prove a worker cannot reach control sockets."),
        ("filesystem-and-scratch-enforcement", "Read-only mounts and bounded private scratch require runtime verification."),
        ("bubblewrap-binary-provenance", "A version string and file metadata do not authenticate the executable."),
        ("complete-runtime-containment", "No worker was launched; effective isolation and cleanup remain unverified."),
    )
    for check, detail in assumptions:
        evidence.append(ValidatedEvidence(
            check, CheckState.UNVERIFIED, EvidenceSource.CONFIGURATION_ASSUMPTION,
            detail, _issuer=_ISSUER,
        ))

    unverified = tuple(
        item.check for item in evidence if item.state is CheckState.UNVERIFIED
    )
    failures = tuple(
        item.check for item in evidence if item.state is CheckState.FAILED
    )
    return HostPreflightReport(
        tuple(raw_records), tuple(evidence), unverified, failures,
        collected_at,
        not injected_reader and type(active_reader) is LinuxHostReader,
        _issuer=_ISSUER,
    )


def systemd_255_property_allowlist() -> frozenset[str]:
    """Return the compiler allowlist; host compatibility is not implied."""

    return SYSTEMD_255_PROPERTIES
