from dataclasses import FrozenInstanceError, replace
from uuid import uuid4

import pytest

from gvai.linux_containment_identity import ContainmentIdentity
import gvai.systemd_worker_profile as worker_profile
from gvai.systemd_worker_contract import ResourceLimits, WorkerIdentity, WorkerSpec
from gvai.systemd_worker_profile import (
    REQUIRED_BWRAP_OPTIONS,
    REQUIRED_CGROUP_CONTROLLERS,
    REQUIRED_NAMESPACES,
    RUNTIME_MOUNTS,
    SYSTEMD_255_PROPERTIES,
    TrustedWorkerPaths,
    VerifiedHostCapabilities,
    WORKER_SECCOMP_POLICY_ID,
    WorkerProfileRejected,
    compile_worker_profile,
    validate_systemd_255_properties,
)


def worker(*, uid=60001, inode=91, limits=None):
    boot = uuid4()
    return WorkerSpec(
        WorkerIdentity(uuid4(), boot, ContainmentIdentity(8, inode)),
        uid,
        uid,
        limits or ResourceLimits(64 * 1024**2, 32, 200, 16 * 1024**2),
    )


def host(**changes):
    fields = {
        "systemd_version": 255,
        "cgroup_v2": True,
        "cgroup_controllers": REQUIRED_CGROUP_CONTROLLERS,
        "namespaces": REQUIRED_NAMESPACES,
        "bwrap_options": REQUIRED_BWRAP_OPTIONS,
        "runtime_mounts": frozenset(RUNTIME_MOUNTS),
        "apparmor_enforcing": True,
        "apparmor_profile_loaded": True,
        "apparmor_profile_name": "gvai-worker",
        "seccomp_no_spawn": True,
        "seccomp_no_sockets": True,
        "seccomp_policy_id": WORKER_SECCOMP_POLICY_ID,
        "unprivileged_user_namespace": True,
        "nested_user_namespace": True,
        "pid_init_reaper": True,
        "manager_outside_worker_containment": True,
        "supervisor_loss_cleanup": True,
        "descriptor_isolation": True,
        "worker_uid_range": (60000, 61000),
        "worker_gid_range": (60000, 61000),
        "occupied_worker_uids": frozenset(),
        "occupied_worker_gids": frozenset(),
        "occupied_worker_cgroups": frozenset(),
    }
    fields.update(changes)
    return VerifiedHostCapabilities(**fields)


def compile(spec=None, capabilities=None, paths=None):
    return compile_worker_profile(
        spec or worker(),
        capabilities or host(),
        paths or TrustedWorkerPaths("/var/lib/gvai/inputs/job-1"),
    )


def test_compiles_fixed_systemd_and_bubblewrap_intent_without_authority():
    spec = worker()
    plan = compile(spec)
    properties = dict((entry.name, entry.value) for entry in plan.properties)

    assert plan.service == spec.identity.service
    assert plan.service.startswith("gvai-worker-")
    assert properties["User"] == str(spec.uid)
    assert properties["Group"] == str(spec.gid)
    assert properties["CapabilityBoundingSet"] == ""
    assert properties["AmbientCapabilities"] == ""
    assert properties["NoNewPrivileges"] == "yes"
    assert properties["AppArmorProfile"] == "gvai-worker"
    assert properties["MemoryMax"] == str(spec.limits.memory_bytes)
    assert properties["TasksMax"] == str(spec.limits.tasks)
    assert properties["CPUQuota"] == f"{spec.limits.cpu_quota_percent}%"
    assert properties["KillMode"] == "control-group"
    assert "PrivatePIDs" not in properties
    assert set(properties) <= SYSTEMD_255_PROPERTIES
    assert "ExecStart" not in properties

    args = plan.bubblewrap_arguments
    assert "--clearenv" in args
    for namespace in ("user", "pid", "net", "uts", "ipc"):
        assert f"--unshare-{namespace}" in args
    assert "--ro-bind" in args
    assert "/var/lib/gvai/inputs/job-1" not in args
    assert "/input" not in args
    assert ("--size", str(spec.limits.scratch_bytes)) in tuple(
        zip(args, args[1:])
    )
    assert ("--tmpfs", "/scratch") in tuple(zip(args, args[1:]))
    assert "--seccomp" not in args
    assert plan.runtime_obligations
    assert all(type(item) is str and item for item in plan.runtime_obligations)
    assert plan.runtime_verified is False
    assert plan.input_path_pinned is False
    assert plan.seccomp_policy_installed is False
    assert plan.contained is False
    assert plan.runnable is False
    assert plan.execution_authorized is False
    assert plan.output_publication_authorized is False
    assert bool(plan) is False


def test_plan_is_immutable_and_property_mapping_is_exact():
    plan = compile()
    properties = {entry.name: entry.value for entry in plan.properties}
    validate_systemd_255_properties(properties, worker())

    with pytest.raises(FrozenInstanceError):
        plan.service = "attacker.service"
    with pytest.raises(AttributeError):
        plan.properties.append("ExecStart")


def test_rejects_unknown_and_unsupported_systemd_properties():
    spec = worker()
    properties = {
        entry.name: entry.value for entry in compile(spec).properties
    }
    for name in ("PrivatePIDs", "ExecStart", "UnknownProperty"):
        with pytest.raises(WorkerProfileRejected):
            validate_systemd_255_properties({**properties, name: "yes"}, spec)


def test_property_validator_rejects_unbounded_worker_limits():
    spec = worker(limits=ResourceLimits((1 << 64) - 1, 10, 10, 10))
    with pytest.raises(WorkerProfileRejected):
        validate_systemd_255_properties({}, spec)


@pytest.mark.parametrize("version", [254, 256, "255"])
def test_rejects_systemd_versions_other_than_exactly_255(version):
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(systemd_version=version))


@pytest.mark.parametrize("namespace", sorted(REQUIRED_NAMESPACES))
def test_rejects_missing_namespace_support(namespace):
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(namespaces=REQUIRED_NAMESPACES - {namespace}))


@pytest.mark.parametrize("controller", sorted(REQUIRED_CGROUP_CONTROLLERS))
def test_rejects_missing_cgroup_controller(controller):
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(
            cgroup_controllers=REQUIRED_CGROUP_CONTROLLERS - {controller},
        ))


@pytest.mark.parametrize("option", sorted(REQUIRED_BWRAP_OPTIONS))
def test_rejects_missing_bubblewrap_feature(option):
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(bwrap_options=REQUIRED_BWRAP_OPTIONS - {option}))


@pytest.mark.parametrize("mount", RUNTIME_MOUNTS)
def test_rejects_missing_runtime_mount(mount):
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(runtime_mounts=frozenset(RUNTIME_MOUNTS) - {mount}))


@pytest.mark.parametrize("capability", [
    "apparmor_enforcing",
    "apparmor_profile_loaded",
    "seccomp_no_spawn",
    "seccomp_no_sockets",
    "unprivileged_user_namespace",
    "nested_user_namespace",
    "pid_init_reaper",
    "manager_outside_worker_containment",
    "supervisor_loss_cleanup",
    "descriptor_isolation",
    "cgroup_v2",
])
def test_rejects_missing_mandatory_protection(capability):
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(**{capability: False}))


def test_rejects_unknown_host_capability_names():
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(namespaces=REQUIRED_NAMESPACES | {"future"}))
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(cgroup_controllers=REQUIRED_CGROUP_CONTROLLERS | {"future"}))
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(bwrap_options=REQUIRED_BWRAP_OPTIONS | {"future"}))
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(apparmor_profile_name="different-profile"))
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(seccomp_policy_id="unknown-policy"))


def test_host_seccomp_claims_do_not_establish_policy_installation():
    spec = worker()
    capabilities = host(
        seccomp_no_spawn=True,
        seccomp_no_sockets=True,
        seccomp_policy_id=WORKER_SECCOMP_POLICY_ID,
    )
    plan = compile(spec, capabilities)

    assert plan.seccomp_policy_installed is False
    assert plan.runnable is False
    assert "--seccomp" not in plan.bubblewrap_arguments
    assert any(
        "descriptor provenance" in item
        for item in plan.runtime_obligations
    )


@pytest.mark.parametrize("seccomp_fd", [3, 4, -1])
def test_untrusted_or_wrong_seccomp_fd_cannot_enter_compiler_plan(seccomp_fd):
    with pytest.raises(TypeError):
        host(seccomp_fd=seccomp_fd)
    with pytest.raises(TypeError):
        TrustedWorkerPaths("/var/lib/gvai/inputs/job-1", input_fd=4)

    plan = compile()
    assert "--seccomp" not in plan.bubblewrap_arguments
    assert "3" not in plan.bubblewrap_arguments
    assert not hasattr(plan, "seccomp_fd")


def test_forged_host_claims_do_not_satisfy_runtime_prerequisites():
    claims = replace(
        host(),
        seccomp_no_spawn=True,
        seccomp_no_sockets=True,
        seccomp_policy_id=WORKER_SECCOMP_POLICY_ID,
    )
    plan = compile(capabilities=claims)

    assert plan.runtime_verified is False
    assert plan.seccomp_policy_installed is False
    assert plan.input_path_pinned is False
    assert plan.runnable is False
    assert plan.all_runtime_obligations_satisfied is False
    assert plan.unresolved_runtime_obligations == plan.runtime_obligations
    assert any(WORKER_SECCOMP_POLICY_ID in item for item in plan.runtime_obligations)


@pytest.mark.parametrize("uid,occupied", [
    (1, frozenset()),
    (60002, frozenset({60002})),
    (70000, frozenset()),
])
def test_rejects_root_duplicate_or_out_of_range_uid(uid, occupied):
    with pytest.raises(WorkerProfileRejected):
        compile(spec=worker(uid=uid), capabilities=host(occupied_worker_uids=occupied))


def test_rejects_duplicate_cgroup_identity():
    spec = worker()
    cgroup = (spec.identity.cgroup.device, spec.identity.cgroup.inode)
    with pytest.raises(WorkerProfileRejected):
        compile(spec, host(occupied_worker_cgroups=frozenset({cgroup})))


def test_rejects_duplicate_or_out_of_range_worker_gid():
    spec = worker()
    with pytest.raises(WorkerProfileRejected):
        compile(spec, host(occupied_worker_gids=frozenset({spec.gid})))
    with pytest.raises(WorkerProfileRejected):
        compile(spec, host(worker_gid_range=(60010, 61000)))


@pytest.mark.parametrize("limits", [
    ResourceLimits((1 << 64) - 1, 10, 10, 10),
    ResourceLimits(1024, (1 << 31), 10, 10),
    ResourceLimits(1024, 10, 100_001, 10),
    ResourceLimits(1024, 10, 10, (1 << 63)),
])
def test_rejects_resource_limit_overflow(limits):
    with pytest.raises(WorkerProfileRejected):
        compile(spec=worker(limits=limits))


@pytest.mark.parametrize("path", [
    "/",
    "/var/lib/gvai/inputs/../secret",
    "/var/lib/gvai/inputs/a/../../etc",
    "/var/lib/gvai/inputs//job",
    "/var/lib/gvai/inputs/job/.",
    "/var/lib/gvai/inputs/job\nname",
    "/proc/self/fd/3",
    "relative/input",
    "/workspace/untrusted",
])
def test_rejects_path_traversal_and_untrusted_input_mounts(path):
    with pytest.raises(WorkerProfileRejected):
        compile(paths=TrustedWorkerPaths(path))


def test_only_read_only_mounts_and_bounded_private_scratch_are_planned():
    plan = compile()
    args = plan.bubblewrap_arguments
    bind_options = [args[index] for index, value in enumerate(args) if value in ("--bind", "--ro-bind")]
    assert bind_options
    assert set(bind_options) == {"--ro-bind"}
    assert "--remount-ro" in args
    assert "--size" in args
    assert "--tmpfs" in args
    assert "--seccomp" not in args
    assert "/input" not in args
    assert "--bind" not in args
    assert "/run" not in args
    binds = [
        tuple(args[index + 1:index + 3])
        for index, value in enumerate(args[:-2])
        if value in ("--bind", "--ro-bind")
    ]
    assert ("/", "/") not in binds
    assert any("descriptor" in item.lower() for item in plan.runtime_obligations)
    assert any("replacement races" in item for item in plan.runtime_obligations)
    assert any("no-symlink resolution" in item for item in plan.runtime_obligations)
    assert any("seccomp policy" in item for item in plan.runtime_obligations)
    assert any("reaper" in item.lower() for item in plan.runtime_obligations)
    assert any("supervisor loss" in item.lower() for item in plan.runtime_obligations)


def test_rejects_malformed_worker_spec_and_non_boolean_host_claims():
    with pytest.raises(WorkerProfileRejected):
        compile(spec=object())
    with pytest.raises(ValueError):
        worker(uid=0)
    with pytest.raises(WorkerProfileRejected):
        compile(capabilities=host(apparmor_enforcing="yes"))


def test_profile_never_claims_runtime_evidence_or_execution_authority():
    plan = compile()
    assert len(plan.runtime_obligations) >= 15
    assert all(
        token in " ".join(plan.runtime_obligations).lower()
        for token in ("namespace", "apparmor", "seccomp", "cgroup", "reap", "stop", "publication")
    )
    assert not hasattr(plan, "evidence")
    assert not hasattr(plan, "authenticated")


def test_symlink_escape_is_never_pinned_or_emitted(tmp_path, monkeypatch):
    trusted_root = tmp_path / "inputs"
    trusted_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = trusted_root / "job"
    link.symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(worker_profile, "INPUT_ROOT", str(trusted_root))

    spec = worker()
    plan = compile(
        spec=spec,
        paths=TrustedWorkerPaths(str(link)),
    )

    assert plan.input_path_pinned is False
    assert str(link) not in plan.bubblewrap_arguments
    assert str(outside) not in plan.bubblewrap_arguments
    assert "/input" not in plan.bubblewrap_arguments
    assert any("no-symlink resolution" in item for item in plan.runtime_obligations)
    assert plan.unresolved_runtime_obligations == plan.runtime_obligations


def test_symlink_replacement_race_cannot_change_or_authorize_plan(tmp_path, monkeypatch):
    trusted_root = tmp_path / "inputs"
    trusted_root.mkdir()
    first_target = tmp_path / "first"
    second_target = tmp_path / "second"
    first_target.mkdir()
    second_target.mkdir()
    link = trusted_root / "job"
    link.symlink_to(first_target, target_is_directory=True)
    monkeypatch.setattr(worker_profile, "INPUT_ROOT", str(trusted_root))

    spec = worker()
    capabilities = host()
    before = compile(spec, capabilities, TrustedWorkerPaths(str(link)))
    link.unlink()
    link.symlink_to(second_target, target_is_directory=True)
    after = compile(spec, capabilities, TrustedWorkerPaths(str(link)))

    assert before == after
    assert before.input_path_pinned is False
    assert before.runnable is False
    assert str(first_target) not in before.bubblewrap_arguments
    assert str(second_target) not in after.bubblewrap_arguments
