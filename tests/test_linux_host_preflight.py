import errno
import os
import socket
import stat
from types import SimpleNamespace

import pytest

from gvai.linux_host_preflight import (
    APPARMOR_PROFILES,
    CGROUP_CONTROLLERS,
    CGROUP_ROOT,
    CONTROL_PATHS,
    CheckState,
    EvidenceSource,
    FileFacts,
    HostPreflightReport,
    LinuxHostReader,
    MAX_OBSERVATION_BYTES,
    NAMESPACE_PATHS,
    PROCESS_STATUS,
    RUNTIME_MOUNTINFO,
    RUNTIME_MOUNTS,
    SECCOMP_ACTIONS,
    SECCOMP_POLICY_ID_PATH,
    VERSION_EXECUTABLES,
    WORKER_ID_CONFIG,
    WORKER_SECCOMP_POLICY_ID,
    RawObservation,
    ValidatedEvidence,
    collect_linux_host_preflight,
    systemd_255_property_allowlist,
)


def directory_facts(inode, device=42):
    return FileFacts(device, inode, stat.S_IFDIR | 0o755, 0, 0)


class FakeHostReader:
    def __init__(self):
        self.texts = {
            "/proc/sys/kernel/osrelease": "6.8.0-31-generic\n",
            RUNTIME_MOUNTINFO: (
                "29 23 0:42 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime "
                "- cgroup2 cgroup rw\n"
            ),
            CGROUP_CONTROLLERS: "cpu cpuset memory pids\n",
            APPARMOR_PROFILES: f"{WORKER_SECCOMP_POLICY_ID} (complain)\ngvai-worker (enforce)\n",
            SECCOMP_ACTIONS: "kill_process kill_thread trap errno trace log allow\n",
            PROCESS_STATUS: "NoNewPrivs:\t0\nCapEff:\t0000000000000000\n",
            SECCOMP_POLICY_ID_PATH: WORKER_SECCOMP_POLICY_ID + "\n",
            WORKER_ID_CONFIG: "uid_min=60000\nuid_max=61000\ngid_min=60000\ngid_max=61000\n",
        }
        self.facts = {
            CGROUP_ROOT: directory_facts(11),
            VERSION_EXECUTABLES["bubblewrap"]: FileFacts(
                42, 12, stat.S_IFREG | 0o755, 0, 0,
            ),
            **{
                path: FileFacts(42, index + 20, stat.S_IFLNK | 0o777, 0, 0)
                for index, path in enumerate(NAMESPACE_PATHS.values())
            },
            **{
                path: directory_facts(index + 40)
                for index, path in enumerate(RUNTIME_MOUNTS)
            },
            **{
                path: FileFacts(42, index + 50, stat.S_IFSOCK | 0o777, 0, 0)
                for index, path in enumerate(CONTROL_PATHS)
            },
            "/var/lib/gvai/scratch": directory_facts(60),
        }
        self.versions = {
            "systemd": "systemd 255 (255.4-1ubuntu8)\n",
            "bubblewrap": "bubblewrap 0.8.0\n",
        }
        self.calls = []

    def read_text(self, path, max_bytes):
        self.calls.append(("read", path, max_bytes))
        value = self.texts[path]
        if isinstance(value, BaseException):
            raise value
        if type(value) is not str:
            return value
        return value

    def file_facts(self, path):
        self.calls.append(("stat", path))
        value = self.facts[path]
        if isinstance(value, BaseException):
            raise value
        return value

    def version_output(self, name):
        self.calls.append(("version", name))
        value = self.versions[name]
        if isinstance(value, BaseException):
            raise value
        return value


def evidence_for(report, check):
    return next(item for item in report.validated_evidence if item.check == check)


def test_collects_allowlisted_provenance_but_never_produces_readiness():
    reader = FakeHostReader()
    report = collect_linux_host_preflight(reader)

    assert report.raw_observations
    assert all(item.source in EvidenceSource for item in report.raw_observations)
    assert all(
        item.source is EvidenceSource.INJECTED_TEST_READER
        for item in report.raw_observations
    )
    assert report.observations_from_trusted_local_reader is False
    assert evidence_for(report, "kernel-version").state is CheckState.VERIFIED
    assert evidence_for(report, "systemd-version").state is CheckState.VERIFIED
    assert evidence_for(report, "bubblewrap-version").state is CheckState.VERIFIED
    assert evidence_for(report, "cgroup2-mount").state is CheckState.VERIFIED
    assert evidence_for(report, "cgroup2-controllers").state is CheckState.VERIFIED
    assert evidence_for(report, "cgroup2-filesystem-identity").state is CheckState.VERIFIED
    assert evidence_for(report, "apparmor-profile").state is CheckState.VERIFIED
    assert evidence_for(report, "seccomp-actions").state is CheckState.VERIFIED
    assert evidence_for(report, "approved-seccomp-policy").state is CheckState.UNVERIFIED
    assert evidence_for(report, "manager-separation").state is CheckState.UNVERIFIED
    assert report.unverified_requirements
    assert report.ready_to_run is False
    assert report.execution_authorized is False
    assert report.output_publication_authorized is False
    assert report.all_requirements_verified is False
    assert report.trusted_worker_capabilities is None
    assert report.is_stale(60, report.collected_at_monotonic_ns) is False
    assert report.is_stale(1, report.collected_at_monotonic_ns + 2_000_000_000) is True
    assert all(call[2] == MAX_OBSERVATION_BYTES for call in reader.calls if call[0] == "read")


def test_all_observations_use_fixed_paths_and_fixed_version_query_names():
    reader = FakeHostReader()
    collect_linux_host_preflight(reader)

    assert {call[1] for call in reader.calls if call[0] == "version"} == {"systemd", "bubblewrap"}
    allowed_calls = (
        set(reader.texts) | set(reader.facts) | set(VERSION_EXECUTABLES.values())
        | {"systemd", "bubblewrap"}
    )
    assert all(call[1] in allowed_calls for call in reader.calls)
    assert "systemctl" not in repr(reader.calls)
    assert not any(call[0] == "version" and "dbus" in call[1].lower() for call in reader.calls)


@pytest.mark.parametrize("path", [
    "/proc/sys/kernel/osrelease",
    RUNTIME_MOUNTINFO,
    CGROUP_CONTROLLERS,
    APPARMOR_PROFILES,
    SECCOMP_ACTIONS,
    PROCESS_STATUS,
])
def test_missing_kernel_interfaces_remain_unverified(path):
    reader = FakeHostReader()
    reader.texts[path] = FileNotFoundError(path)
    report = collect_linux_host_preflight(reader)

    check = next(item.check for item in report.raw_observations if item.value is None)
    assert evidence_for(report, check).state is CheckState.UNVERIFIED
    assert report.ready_to_run is False
    assert report.trusted_worker_capabilities is None


def test_permission_failures_remain_unverified_not_success():
    reader = FakeHostReader()
    reader.texts[APPARMOR_PROFILES] = PermissionError(errno.EACCES, "denied")
    reader.facts[CGROUP_ROOT] = PermissionError(errno.EACCES, "denied")
    report = collect_linux_host_preflight(reader)

    assert evidence_for(report, "apparmor-profile").state is CheckState.UNVERIFIED
    assert evidence_for(report, "cgroup-root-identity").state is CheckState.UNVERIFIED
    assert report.ready_to_run is False


def test_missing_namespace_handles_do_not_prove_namespace_creation():
    reader = FakeHostReader()
    first_namespace_path = next(iter(NAMESPACE_PATHS.values()))
    reader.facts[first_namespace_path] = FileNotFoundError(first_namespace_path)
    report = collect_linux_host_preflight(reader)

    assert evidence_for(report, f"namespace-handle-{next(iter(NAMESPACE_PATHS))}").state is CheckState.UNVERIFIED
    assert evidence_for(report, "namespace-creation-support").state is CheckState.UNVERIFIED
    assert report.ready_to_run is False


def test_malformed_observations_and_forged_evidence_are_rejected():
    reader = FakeHostReader()
    reader.texts["/proc/sys/kernel/osrelease"] = {"kernel": "6.8"}
    reader.facts[CGROUP_ROOT] = {"device": 42, "inode": 11}
    report = collect_linux_host_preflight(reader)

    assert evidence_for(report, "kernel-version").state is CheckState.UNVERIFIED
    assert evidence_for(report, "cgroup-root-identity").state is CheckState.UNVERIFIED
    with pytest.raises(ValueError, match="issued"):
        RawObservation(
            "kernel-version", EvidenceSource.KERNEL_INTERFACE, "6.8",
        )
    with pytest.raises(ValueError, match="issued"):
        ValidatedEvidence(
            "kernel-version", CheckState.VERIFIED,
            EvidenceSource.KERNEL_INTERFACE, "forged",
        )
    with pytest.raises(ValueError, match="issued"):
        HostPreflightReport((), (), (), (), 1, False)


def test_wrong_or_duplicate_cgroup_mount_identity_fails_closed():
    reader = FakeHostReader()
    reader.texts[RUNTIME_MOUNTINFO] = (
        "29 23 0:43 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
    )
    report = collect_linux_host_preflight(reader)
    assert evidence_for(report, "cgroup2-filesystem-identity").state is CheckState.FAILED
    assert report.ready_to_run is False

    reader.texts[RUNTIME_MOUNTINFO] += (
        "30 23 0:42 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n"
    )
    report = collect_linux_host_preflight(reader)
    assert evidence_for(report, "cgroup2-mount").state is CheckState.FAILED
    assert evidence_for(report, "cgroup2-filesystem-identity").state is CheckState.FAILED


def test_missing_or_duplicate_required_cgroup_controllers_fail():
    reader = FakeHostReader()
    reader.texts[CGROUP_CONTROLLERS] = "cpu memory\n"
    report = collect_linux_host_preflight(reader)
    assert evidence_for(report, "cgroup2-controllers").state is CheckState.FAILED

    reader.texts[CGROUP_CONTROLLERS] = "cpu memory pids pids\n"
    report = collect_linux_host_preflight(reader)
    assert evidence_for(report, "cgroup2-controllers").state is CheckState.FAILED


@pytest.mark.parametrize("profile", [
    "gvai-worker (complain)\n",
    "gvai-worker (disabled)\n",
    "gvai-worker (enforce)\ngvai-worker (complain)\n",
])
def test_apparmor_not_exactly_enforcing_fails(profile):
    reader = FakeHostReader()
    reader.texts[APPARMOR_PROFILES] = profile
    report = collect_linux_host_preflight(reader)
    assert evidence_for(report, "apparmor-profile").state is CheckState.FAILED
    assert report.ready_to_run is False


def test_wrong_seccomp_policy_identity_and_worker_id_configuration_fail():
    reader = FakeHostReader()
    reader.texts[SECCOMP_POLICY_ID_PATH] = "attacker-policy-v9\n"
    reader.texts[WORKER_ID_CONFIG] = "uid_min=0\nuid_max=10\ngid_min=0\ngid_max=10\n"
    report = collect_linux_host_preflight(reader)

    assert evidence_for(report, "seccomp-policy-id-configuration").state is CheckState.FAILED
    assert evidence_for(report, "worker-id-range-configuration").state is CheckState.FAILED
    assert evidence_for(report, "approved-seccomp-policy").state is CheckState.UNVERIFIED
    assert report.ready_to_run is False


def test_missing_bubblewrap_is_unverified_and_never_ready():
    reader = FakeHostReader()
    reader.versions["bubblewrap"] = FileNotFoundError("bwrap missing")
    reader.facts[VERSION_EXECUTABLES["bubblewrap"]] = FileNotFoundError("bwrap missing")
    report = collect_linux_host_preflight(reader)

    assert evidence_for(report, "bubblewrap-version").state is CheckState.UNVERIFIED
    assert evidence_for(report, "bubblewrap-file-identity").state is CheckState.UNVERIFIED
    assert report.ready_to_run is False


def test_wrong_systemd_and_bubblewrap_versions_fail_closed():
    reader = FakeHostReader()
    reader.versions["systemd"] = "systemd 256\n"
    reader.versions["bubblewrap"] = "bubblewrap not-a-version\n"
    report = collect_linux_host_preflight(reader)

    assert evidence_for(report, "systemd-version").state is CheckState.FAILED
    assert evidence_for(report, "bubblewrap-version").state is CheckState.FAILED
    assert evidence_for(report, "systemd-255-property-compatibility").state is CheckState.UNVERIFIED
    assert report.ready_to_run is False


def test_duplicate_process_status_fields_are_contradictory():
    reader = FakeHostReader()
    reader.texts[PROCESS_STATUS] = (
        "NoNewPrivs:\t0\nNoNewPrivs:\t1\nCapEff:\t00000000\n"
    )
    report = collect_linux_host_preflight(reader)

    assert evidence_for(report, "process-privilege-observation").state is CheckState.FAILED
    assert evidence_for(report, "worker-no-new-privileges-and-capabilities").state is CheckState.UNVERIFIED
    assert report.ready_to_run is False


def test_symlink_and_path_substitution_fail_closed_in_local_reader(tmp_path, monkeypatch):
    target = tmp_path / "real"
    target.write_text("forged kernel version\n", encoding="utf-8")
    link = tmp_path / "osrelease"
    link.symlink_to(target)
    monkeypatch.setattr(
        "gvai.linux_host_preflight._ALLOWED_TEXT_PATHS",
        frozenset({str(link)}),
    )
    reader = LinuxHostReader()

    with pytest.raises(OSError):
        reader.read_text(str(link), 128)
    with pytest.raises(ValueError):
        reader.read_text(str(link), MAX_OBSERVATION_BYTES + 1)
    monkeypatch.setattr(
        "gvai.linux_host_preflight._ALLOWED_STAT_PATHS",
        frozenset({str(link)}),
    )
    facts = reader.file_facts(str(link))
    assert stat.S_ISLNK(facts.mode)
    assert not stat.S_ISDIR(facts.mode)


def test_symlinked_parent_component_is_not_followed(tmp_path, monkeypatch):
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "kernel").write_text("6.8.0\n", encoding="utf-8")
    parent_link = tmp_path / "substituted"
    parent_link.symlink_to(actual, target_is_directory=True)
    target = parent_link / "kernel"
    monkeypatch.setattr(
        "gvai.linux_host_preflight._ALLOWED_TEXT_PATHS",
        frozenset({str(target)}),
    )

    with pytest.raises(OSError):
        LinuxHostReader().read_text(str(target), 128)


def test_fifo_substitution_is_opened_nonblocking_then_rejected(tmp_path, monkeypatch):
    fifo = tmp_path / "observation"
    os.mkfifo(fifo)
    monkeypatch.setattr(
        "gvai.linux_host_preflight._ALLOWED_TEXT_PATHS",
        frozenset({str(fifo)}),
    )

    with pytest.raises(OSError, match="not a regular"):
        LinuxHostReader().read_text(str(fifo), 128)


def test_unix_socket_substitution_fails_without_reading(tmp_path, monkeypatch):
    socket_path = tmp_path / "observation.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(socket_path))
        monkeypatch.setattr(
            "gvai.linux_host_preflight._ALLOWED_TEXT_PATHS",
            frozenset({str(socket_path)}),
        )
        with pytest.raises(OSError):
            LinuxHostReader().read_text(str(socket_path), 128)
    finally:
        server.close()


@pytest.mark.parametrize("mode", [
    stat.S_IFCHR | 0o600,
    stat.S_IFBLK | 0o600,
    stat.S_IFSOCK | 0o600,
    stat.S_IFIFO | 0o600,
])
def test_non_regular_fstat_types_are_rejected_before_read(tmp_path, monkeypatch, mode):
    source = tmp_path / "observation"
    source.write_text("would not be read", encoding="utf-8")
    monkeypatch.setattr(
        "gvai.linux_host_preflight._ALLOWED_TEXT_PATHS",
        frozenset({str(source)}),
    )
    monkeypatch.setattr(
        "gvai.linux_host_preflight.os.fstat",
        lambda descriptor: SimpleNamespace(st_mode=mode),
    )

    with pytest.raises(OSError, match="not a regular"):
        LinuxHostReader().read_text(str(source), 128)


def test_short_reads_are_accumulated_until_eof(tmp_path, monkeypatch):
    source = tmp_path / "observation"
    source.write_text("abcdefghij", encoding="utf-8")
    monkeypatch.setattr(
        "gvai.linux_host_preflight._ALLOWED_TEXT_PATHS",
        frozenset({str(source)}),
    )
    real_read = os.read
    sizes = []

    def short_read(descriptor, size):
        sizes.append(size)
        return real_read(descriptor, min(size, 3))

    monkeypatch.setattr("gvai.linux_host_preflight.os.read", short_read)

    assert LinuxHostReader().read_text(str(source), 10) == "abcdefghij"
    assert len(sizes) > 1


def test_oversized_regular_file_is_rejected_after_bounded_read(tmp_path, monkeypatch):
    source = tmp_path / "observation"
    source.write_text("abcdefghijk", encoding="utf-8")
    monkeypatch.setattr(
        "gvai.linux_host_preflight._ALLOWED_TEXT_PATHS",
        frozenset({str(source)}),
    )
    real_read = os.read
    total = 0

    def bounded_read(descriptor, size):
        nonlocal total
        chunk = real_read(descriptor, size)
        total += len(chunk)
        return chunk

    monkeypatch.setattr("gvai.linux_host_preflight.os.read", bounded_read)

    with pytest.raises(ValueError, match="size limit"):
        LinuxHostReader().read_text(str(source), 10)
    assert total <= 11


def test_read_errors_and_fstat_errors_are_closed_as_errors(tmp_path, monkeypatch):
    source = tmp_path / "observation"
    source.write_text("valid", encoding="utf-8")
    monkeypatch.setattr(
        "gvai.linux_host_preflight._ALLOWED_TEXT_PATHS",
        frozenset({str(source)}),
    )
    monkeypatch.setattr(
        "gvai.linux_host_preflight.os.read",
        lambda descriptor, size: (_ for _ in ()).throw(PermissionError(errno.EACCES, "denied")),
    )
    with pytest.raises(PermissionError):
        LinuxHostReader().read_text(str(source), 128)

    monkeypatch.undo()
    monkeypatch.setattr(
        "gvai.linux_host_preflight._ALLOWED_TEXT_PATHS",
        frozenset({str(source)}),
    )
    monkeypatch.setattr(
        "gvai.linux_host_preflight.os.fstat",
        lambda descriptor: (_ for _ in ()).throw(OSError("bad descriptor")),
    )
    with pytest.raises(OSError, match="bad descriptor"):
        LinuxHostReader().read_text(str(source), 128)


def test_unsupported_systemd_property_names_are_not_in_host_allowlist():
    allowed = systemd_255_property_allowlist()
    assert "PrivatePIDs" not in allowed
    assert "ExecStart" not in allowed
    assert "UnknownProperty" not in allowed
    assert "ProtectSystem" in allowed


def test_syntactically_valid_fake_success_cannot_become_trusted_capability_evidence():
    report = collect_linux_host_preflight(FakeHostReader())
    observed_successes = [
        item for item in report.validated_evidence
        if item.state is CheckState.VERIFIED
    ]

    assert observed_successes
    assert all(
        item.source is EvidenceSource.INJECTED_TEST_READER
        for item in observed_successes
    )
    assert report.observations_from_trusted_local_reader is False
    assert report.trusted_worker_capabilities is None
    assert report.ready_to_run is False
