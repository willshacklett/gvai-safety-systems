"""Deterministic, non-executing worker security profile compiler."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping

from gvai.systemd_manager_boundary import MAX_SPEC_INTEGER
from gvai.systemd_worker_contract import WorkerSpec, _valid_worker_spec

SYSTEMD_255_PROPERTIES = frozenset({
    "AmbientCapabilities",
    "AppArmorProfile",
    "CapabilityBoundingSet",
    "CPUQuota",
    "Group",
    "KillMode",
    "MemoryDenyWriteExecute",
    "MemoryMax",
    "NoNewPrivileges",
    "PrivateIPC",
    "PrivateNetwork",
    "PrivateUsers",
    "ProtectControlGroups",
    "ProtectHome",
    "ProtectHostname",
    "ProtectKernelModules",
    "ProtectKernelTunables",
    "ProtectSystem",
    "RestrictSUIDSGID",
    "SendSIGKILL",
    "TasksMax",
    "TimeoutStopSec",
    "Type",
    "User",
})

REQUIRED_NAMESPACES = frozenset({
    "user", "pid", "mount", "network", "uts", "ipc",
})
REQUIRED_CGROUP_CONTROLLERS = frozenset({"cpu", "memory", "pids"})
SUPPORTED_CGROUP_CONTROLLERS = frozenset({
    "cpu", "cpuset", "io", "memory", "pids",
})
REQUIRED_BWRAP_OPTIONS = frozenset({
    "cap-drop", "clearenv", "dev", "die-with-parent", "dir", "new-session",
    "proc", "remount-ro", "ro-bind", "seccomp", "size", "tmpfs",
    "unshare-ipc", "unshare-net", "unshare-pid", "unshare-user",
    "unshare-uts", "perms",
})
SUPPORTED_BWRAP_OPTIONS = REQUIRED_BWRAP_OPTIONS
RUNTIME_MOUNTS = ("/usr", "/bin", "/lib", "/lib64")
INPUT_ROOT = "/var/lib/gvai/inputs"
WORKER_APPARMOR_PROFILE = "gvai-worker"
WORKER_SECCOMP_POLICY_ID = "gvai-worker-no-spawn-no-sockets-v1"
MAX_MEMORY_BYTES = (1 << 63) - 1
MAX_SCRATCH_BYTES = (1 << 63) - 1
MAX_TASKS = (1 << 31) - 1
MAX_CPU_QUOTA_PERCENT = 100_000


class WorkerProfileRejected(ValueError):
    """A profile cannot be compiled without weakening a mandatory control."""


@dataclass(frozen=True)
class VerifiedHostCapabilities:
    systemd_version: int
    cgroup_v2: bool
    cgroup_controllers: frozenset[str]
    namespaces: frozenset[str]
    bwrap_options: frozenset[str]
    runtime_mounts: frozenset[str]
    apparmor_enforcing: bool
    apparmor_profile_loaded: bool
    apparmor_profile_name: str
    seccomp_no_spawn: bool
    seccomp_no_sockets: bool
    seccomp_policy_id: str
    unprivileged_user_namespace: bool
    nested_user_namespace: bool
    pid_init_reaper: bool
    manager_outside_worker_containment: bool
    supervisor_loss_cleanup: bool
    descriptor_isolation: bool
    worker_uid_range: tuple[int, int]
    worker_gid_range: tuple[int, int]
    occupied_worker_uids: frozenset[int]
    occupied_worker_gids: frozenset[int]
    occupied_worker_cgroups: frozenset[tuple[int, int]]


@dataclass(frozen=True)
class TrustedWorkerPaths:
    """Trusted lexical selector only; no filesystem pinning is performed here."""

    input_source: str


@dataclass(frozen=True)
class SystemdProperty:
    name: str
    value: str


@dataclass(frozen=True)
class WorkerProfilePlan:
    service: str
    properties: tuple[SystemdProperty, ...]
    bubblewrap_arguments: tuple[str, ...]
    runtime_obligations: tuple[str, ...]

    @property
    def runtime_verified(self) -> bool:
        return False

    @property
    def unresolved_runtime_obligations(self) -> tuple[str, ...]:
        return self.runtime_obligations

    @property
    def all_runtime_obligations_satisfied(self) -> bool:
        return False

    @property
    def input_path_pinned(self) -> bool:
        return False

    @property
    def seccomp_policy_installed(self) -> bool:
        return False

    @property
    def contained(self) -> bool:
        return False

    @property
    def runnable(self) -> bool:
        return False

    @property
    def execution_authorized(self) -> bool:
        return False

    @property
    def output_publication_authorized(self) -> bool:
        return False

    def __bool__(self) -> bool:
        return False


def validate_systemd_255_properties(
    properties: Mapping[str, str],
    spec: WorkerSpec,
) -> None:
    """Accept only the exact property plan generated for this fixed spec."""

    if type(properties) is not dict or not _valid_spec_bounds(spec):
        raise WorkerProfileRejected("Expected a property mapping and valid worker spec.")
    if any(type(name) is not str or name not in SYSTEMD_255_PROPERTIES for name in properties):
        raise WorkerProfileRejected("Unknown or unsupported systemd 255 property.")
    expected = {
        property.name: property.value for property in _systemd_properties(spec)
    }
    if properties != expected:
        raise WorkerProfileRejected("Systemd properties differ from the mandatory plan.")


def _systemd_properties(spec: WorkerSpec) -> tuple[SystemdProperty, ...]:
    values = {
        "AmbientCapabilities": "",
        "AppArmorProfile": WORKER_APPARMOR_PROFILE,
        "CapabilityBoundingSet": "",
        "CPUQuota": f"{spec.limits.cpu_quota_percent}%",
        "Group": str(spec.gid),
        "KillMode": "control-group",
        "MemoryDenyWriteExecute": "yes",
        "MemoryMax": str(spec.limits.memory_bytes),
        "NoNewPrivileges": "yes",
        "PrivateIPC": "yes",
        "PrivateNetwork": "yes",
        "PrivateUsers": "yes",
        "ProtectControlGroups": "yes",
        "ProtectHome": "yes",
        "ProtectHostname": "yes",
        "ProtectKernelModules": "yes",
        "ProtectKernelTunables": "yes",
        "ProtectSystem": "strict",
        "RestrictSUIDSGID": "yes",
        "SendSIGKILL": "yes",
        "TasksMax": str(spec.limits.tasks),
        "TimeoutStopSec": "5s",
        "Type": "exec",
        "User": str(spec.uid),
    }
    return tuple(SystemdProperty(name, values[name]) for name in sorted(values))


def _valid_spec_bounds(spec: object) -> bool:
    if not _valid_worker_spec(spec):
        return False
    return all(value <= MAX_SPEC_INTEGER for value in (
        spec.uid, spec.gid, spec.identity.cgroup.device, spec.identity.cgroup.inode,
        spec.limits.memory_bytes, spec.limits.tasks,
        spec.limits.cpu_quota_percent, spec.limits.scratch_bytes,
    )) and (
        spec.limits.memory_bytes <= MAX_MEMORY_BYTES
        and spec.limits.tasks <= MAX_TASKS
        and spec.limits.cpu_quota_percent <= MAX_CPU_QUOTA_PERCENT
        and spec.limits.scratch_bytes <= MAX_SCRATCH_BYTES
    )


def _validate_host(capabilities: VerifiedHostCapabilities, spec: WorkerSpec) -> None:
    if type(capabilities) is not VerifiedHostCapabilities:
        raise WorkerProfileRejected("Explicit verified host capabilities are required.")
    if type(capabilities.systemd_version) is not int or capabilities.systemd_version != 255:
        raise WorkerProfileRejected("Only the explicitly supported systemd 255 profile is accepted.")
    if any(type(value) is not bool for value in (
        capabilities.cgroup_v2,
        capabilities.apparmor_enforcing,
        capabilities.apparmor_profile_loaded,
        capabilities.seccomp_no_spawn,
        capabilities.seccomp_no_sockets,
        capabilities.unprivileged_user_namespace,
        capabilities.nested_user_namespace,
        capabilities.pid_init_reaper,
        capabilities.manager_outside_worker_containment,
        capabilities.supervisor_loss_cleanup,
        capabilities.descriptor_isolation,
    )):
        raise WorkerProfileRejected("Host capability flags must be explicit booleans.")
    if (
        type(capabilities.apparmor_profile_name) is not str
        or capabilities.apparmor_profile_name != WORKER_APPARMOR_PROFILE
        or type(capabilities.seccomp_policy_id) is not str
        or capabilities.seccomp_policy_id != WORKER_SECCOMP_POLICY_ID
    ):
        raise WorkerProfileRejected("Required AppArmor or seccomp policy identity is unavailable.")
    if (
        type(capabilities.cgroup_controllers) is not frozenset
        or capabilities.cgroup_controllers - SUPPORTED_CGROUP_CONTROLLERS
        or not REQUIRED_CGROUP_CONTROLLERS <= capabilities.cgroup_controllers
    ):
        raise WorkerProfileRejected("Required cgroup v2 controllers are missing or unknown.")
    if (
        type(capabilities.namespaces) is not frozenset
        or capabilities.namespaces - REQUIRED_NAMESPACES
        or not REQUIRED_NAMESPACES <= capabilities.namespaces
    ):
        raise WorkerProfileRejected("Required namespace support is missing or unknown.")
    if (
        type(capabilities.bwrap_options) is not frozenset
        or capabilities.bwrap_options - SUPPORTED_BWRAP_OPTIONS
        or not REQUIRED_BWRAP_OPTIONS <= capabilities.bwrap_options
    ):
        raise WorkerProfileRejected("Required Bubblewrap features are missing or unknown.")
    if (
        type(capabilities.runtime_mounts) is not frozenset
        or capabilities.runtime_mounts - frozenset(RUNTIME_MOUNTS)
        or not frozenset(RUNTIME_MOUNTS) <= capabilities.runtime_mounts
    ):
        raise WorkerProfileRejected("A required read-only runtime mount is unavailable or unknown.")
    if not (
        capabilities.cgroup_v2
        and capabilities.apparmor_enforcing
        and capabilities.apparmor_profile_loaded
        and capabilities.seccomp_no_spawn
        and capabilities.seccomp_no_sockets
        and capabilities.unprivileged_user_namespace
        and capabilities.nested_user_namespace
        and capabilities.pid_init_reaper
        and capabilities.manager_outside_worker_containment
        and capabilities.supervisor_loss_cleanup
        and capabilities.descriptor_isolation
    ):
        raise WorkerProfileRejected("A mandatory host protection prerequisite is absent.")
    uid_range = capabilities.worker_uid_range
    for identity, value, name in (
        (uid_range, spec.uid, "UID"),
        (capabilities.worker_gid_range, spec.gid, "GID"),
    ):
        if (
            type(identity) is not tuple or len(identity) != 2
            or any(type(bound) is not int for bound in identity)
            or identity[0] <= 0 or identity[1] < identity[0]
            or identity[1] > MAX_SPEC_INTEGER
            or not identity[0] <= value <= identity[1]
        ):
            raise WorkerProfileRejected(f"Worker {name} is outside the trusted non-root range.")
    if (
        type(capabilities.occupied_worker_uids) is not frozenset
        or any(
            type(uid) is not int or uid <= 0 or uid > MAX_SPEC_INTEGER
            for uid in capabilities.occupied_worker_uids
        )
        or spec.uid in capabilities.occupied_worker_uids
    ):
        raise WorkerProfileRejected("Worker UID is invalid or already allocated.")
    if (
        type(capabilities.occupied_worker_gids) is not frozenset
        or any(
            type(gid) is not int or gid <= 0 or gid > MAX_SPEC_INTEGER
            for gid in capabilities.occupied_worker_gids
        )
        or spec.gid in capabilities.occupied_worker_gids
    ):
        raise WorkerProfileRejected("Worker GID is invalid or already allocated.")
    identity = (spec.identity.cgroup.device, spec.identity.cgroup.inode)
    if (
        type(capabilities.occupied_worker_cgroups) is not frozenset
        or any(
            type(item) is not tuple or len(item) != 2
            or any(
                type(value) is not int or value < 0 or value > MAX_SPEC_INTEGER
                for value in item
            )
            for item in capabilities.occupied_worker_cgroups
        )
        or identity in capabilities.occupied_worker_cgroups
    ):
        raise WorkerProfileRejected("Worker cgroup identity is invalid or already allocated.")


def _validate_input_path(paths: TrustedWorkerPaths) -> str:
    if type(paths) is not TrustedWorkerPaths or type(paths.input_source) is not str:
        raise WorkerProfileRejected("Trusted input path configuration is required.")
    raw = paths.input_source
    parts = raw.split("/")
    parsed = PurePosixPath(raw)
    if (
        not raw.startswith(INPUT_ROOT + "/")
        or not parsed.is_absolute()
        or parsed.as_posix() != raw
        or any(part in ("", ".", "..") for part in parts[1:])
        or any(ord(character) < 32 or ord(character) == 127 for character in raw)
    ):
        raise WorkerProfileRejected("Input path must be canonical and beneath the trusted input root.")
    return raw


def _bubblewrap_arguments(spec: WorkerSpec) -> tuple[str, ...]:
    # Bubblewrap creates the private mount namespace and empty root itself.
    args = [
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-uts",
        "--unshare-ipc",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ]
    for path in RUNTIME_MOUNTS:
        args.extend(("--ro-bind", path, path))
    args.extend((
        "--dir", "/scratch",
        "--proc", "/proc",
        "--dev", "/dev",
        "--remount-ro", "/",
        "--size", str(spec.limits.scratch_bytes),
        "--perms", "0700",
        "--tmpfs", "/scratch",
        "--cap-drop", "ALL",
    ))
    return tuple(args)


RUNTIME_OBLIGATIONS = (
    "Verify the effective systemd 255 properties on the started unit; a plan is not evidence.",
    "Verify the manager is outside worker namespaces and cgroup and exclusively owns the manager API.",
    "Verify the worker service cgroup is cgroup v2 and its pinned device/inode matches the spec.",
    "Verify cpu.max, memory.max, and pids.max match the compiled resource limits.",
    "Verify actual user, PID, mount, network, UTS, and IPC namespace identities.",
    "Verify the named AppArmor profile is loaded in enforce mode on the worker process.",
    "Verify NoNewPrivs and all effective, permitted, inheritable, bounding, and ambient capabilities.",
    "Resolve the trusted input beneath the fixed input root with race-resistant no-symlink resolution, pin its descriptor, verify descriptor identity, and only then create a read-only input mount.",
    "Prevent symlink traversal and replacement races between input resolution, identity verification, and mount installation.",
    f"Verify the trusted launcher obtained seccomp policy {WORKER_SECCOMP_POLICY_ID} from an approved source, verified its exact identity and descriptor provenance, and installed it before untrusted execution.",
    "Never accept a worker-provided seccomp descriptor, filename, policy description, or self-asserted policy evidence.",
    "Verify root/runtime/input mounts are read-only and no host root, manager socket, or control path is mounted.",
    "Verify scratch is a private tmpfs at the exact size and mode, with no writable host-backed mount.",
    "Verify the worker inherited no STOP, manager, cgroup-control, publication, or unauthorized descriptors.",
    "Verify the PID namespace init/reaper remains alive, accounts for all descendants, and successfully reaps them.",
    "Verify STOP kills the whole worker cgroup and termination plus reaping are both observed.",
    "Verify manager lease expiry or supervisor loss triggers worker termination within the declared deadline.",
    "Verify the manager transport enforces frame byte limits and deadlines before decoding or authenticating replies.",
    "Verify manager peer identity and response freshness using an external authenticated challenge protocol.",
    "Verify the durable STOP journal remains supervisor-owned and all output checks remain denial-only.",
)


def compile_worker_profile(
    spec: WorkerSpec,
    capabilities: VerifiedHostCapabilities,
    paths: TrustedWorkerPaths,
) -> WorkerProfilePlan:
    """Compile deterministic plans; never executes units or establishes evidence."""

    if not _valid_spec_bounds(spec):
        raise WorkerProfileRejected("Invalid worker specification.")
    _validate_host(capabilities, spec)
    _validate_input_path(paths)
    properties = _systemd_properties(spec)
    validate_systemd_255_properties(
        {property.name: property.value for property in properties}, spec,
    )
    return WorkerProfilePlan(
        service=spec.identity.service,
        properties=properties,
        bubblewrap_arguments=_bubblewrap_arguments(spec),
        runtime_obligations=RUNTIME_OBLIGATIONS,
    )
