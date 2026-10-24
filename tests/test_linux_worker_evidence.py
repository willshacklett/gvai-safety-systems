import os
import socket
import subprocess
import threading
from uuid import UUID

import pytest

from gvai.launcher_worker_contract import (
    EvidenceRequest, LifecycleState as S,
)
from gvai.linux_containment_identity import ContainmentIdentity
from gvai.linux_worker_evidence import (
    DescriptorRecord, EvidenceCollection, KernelEvidenceCollector,
    MAX_FIELD_BYTES, NamespaceRecord, ObservationSource, ObservationState,
    ProcessField, ProcessHandleContext,
)
from gvai.systemd_worker_contract import ResourceLimits, WorkerIdentity, WorkerSpec
from gvai.systemd_worker_profile import REQUIRED_NAMESPACES
from gvai.trusted_worker_entry import EntryIdentity, ObjectPin, ProcessLifetime
from gvai.trusted_worker_entry import (
    ArtifactIdentity, MappingPlan, MappingStage, TrustedEntryExchange, VerifierIdentity,
)


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def prohibited(*args, **kwargs):
        pytest.fail("Collector tests must not access the host or execute processes.")

    monkeypatch.setattr(subprocess, "Popen", prohibited)
    monkeypatch.setattr(socket, "socket", prohibited)
    for name in ("kill", "killpg", "waitpid", "waitid", "system", "fork"):
        monkeypatch.setattr(os, name, prohibited)


PID = 123
START = 456
UID = 60001
CGROUP = ObjectPin(8, 91)
PID_NS = ObjectPin(9, 10)
UID_MAP = ((0, UID, 1),)
GID_MAP = ((0, UID, 1),)
DESCRIPTORS = (DescriptorRecord(0, "/dev/null", 0),)


def context():
    spec = WorkerSpec(
        WorkerIdentity(UUID(int=1), UUID(int=2), ContainmentIdentity(*(
            CGROUP.device, CGROUP.inode,
        ))),
        UID, UID, ResourceLimits(64 * 1024**2, 32, 200, 16 * 1024**2),
    )
    request = EvidenceRequest(
        spec, UUID(int=3), 4, S.INPUT_AND_SECCOMP_VERIFIED, S.WORKER_CONFINEMENT_VERIFIED,
    )
    identity = EntryIdentity(
        spec.identity.boot, spec.identity.attempt, spec.identity.service,
        ProcessLifetime(PID, START, PID_NS, b"p" * 32),
        CGROUP, ArtifactIdentity(ObjectPin(8, 92), "a" * 64),
    )
    namespaces = tuple(
        NamespaceRecord(name, PID_NS if name == "pid" else ObjectPin(9, index + 20))
        for index, name in enumerate(sorted(REQUIRED_NAMESPACES))
    )
    return ProcessHandleContext(
        identity, request, 3, 4, 5, DESCRIPTORS,
        UID_MAP, GID_MAP, "deny", namespaces,
    )


def process_status(**changes):
    values = {
        "Uid": f"{UID} {UID} {UID} {UID}",
        "Gid": f"{UID} {UID} {UID} {UID}",
        "NoNewPrivs": "1",
        "Seccomp": "2",
        "CapEff": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapInh": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000",
        "Name": "worker",
    }
    values.update(changes)
    return "".join(f"{key}:\t{value}\n" for key, value in values.items()).encode()


def proc_stat(pid=PID, start=START):
    values = ["0"] * 18 + [str(start)]
    return f"{pid} (worker) S {' '.join(values)}\n".encode()


class FakeReader:
    def __init__(self, *, changes=None, sequences=None, hook=None):
        self.values = {
            ProcessField.STAT: proc_stat(),
            ProcessField.STATUS: process_status(),
            ProcessField.UID_MAP: b"0 60001 1\n",
            ProcessField.GID_MAP: b"0 60001 1\n",
            ProcessField.SETGROUPS: b"deny\n",
            ProcessField.CGROUP: b"0::/worker\n",
            ProcessField.APPARMOR_CURRENT: b"gvai-setup//&gvai-worker (enforce)\n",
        }
        self.changes = changes or {}
        self.sequences = {key: list(value) for key, value in (sequences or {}).items()}
        self.hook = hook
        self.reads = []

    def read_field(self, field, max_bytes):
        assert type(field) is ProcessField
        assert max_bytes == MAX_FIELD_BYTES
        self.reads.append(field)
        if self.hook is not None:
            self.hook(field)
        if field in self.sequences and self.sequences[field]:
            value = self.sequences[field].pop(0)
            if isinstance(value, BaseException):
                raise value
            return value
        value = self.changes.get(field, self.values[field])
        if isinstance(value, BaseException):
            raise value
        return value

    def pidfd_alive(self):
        return self.changes.get("alive", True)

    def pidfd_pid(self):
        return self.changes.get("pid", PID)

    def namespace_identities(self):
        if "namespaces_sequence" in self.sequences and self.sequences["namespaces_sequence"]:
            return self.sequences["namespaces_sequence"].pop(0)
        return self.changes.get("namespaces", context().expected_namespaces)

    def cgroup_identity(self):
        if "cgroup_sequence" in self.sequences and self.sequences["cgroup_sequence"]:
            return self.sequences["cgroup_sequence"].pop(0)
        return self.changes.get("cgroup", CGROUP)

    def cgroup_contains(self, pid):
        assert pid == PID
        if "member_sequence" in self.sequences and self.sequences["member_sequence"]:
            return self.sequences["member_sequence"].pop(0)
        return self.changes.get("member", True)

    def descriptor_inventory(self):
        if "descriptors_sequence" in self.sequences and self.sequences["descriptors_sequence"]:
            return self.sequences["descriptors_sequence"].pop(0)
        return self.changes.get("descriptors", DESCRIPTORS)


def collect(reader=None, **changes):
    return KernelEvidenceCollector().collect(context(), reader or FakeReader(changes=changes))


def test_fake_reader_is_structurally_observed_but_never_authenticated():
    report = collect(FakeReader())
    assert report.state is ObservationState.UNVERIFIED
    assert report.source is ObservationSource.INJECTED_TEST_READER
    assert report.facts.pid == PID and report.facts.start_ticks == START
    assert report.facts.no_new_privs and report.facts.seccomp_mode == 2
    assert report.facts.capabilities and all(value == 0 for _, value in report.facts.capabilities)
    assert report.authenticated is False and report.runtime_verified is False
    assert report.execution_authorized is False and report.output_publication_authorized is False
    assert not report


@pytest.mark.parametrize("changes", [
    {"pid": 124},
    {ProcessField.STAT: proc_stat(pid=124)},
    {ProcessField.STAT: proc_stat(start=457)},
    {"cgroup": ObjectPin(8, 92)},
    {"member": False},
    {"descriptors": ()},
    {"namespaces": ()},
    {"namespaces": (NamespaceRecord("pid", ObjectPin(9, 999)),)},
    {ProcessField.STATUS: process_status(Uid="60001 60002 60001 60001")},
    {ProcessField.STATUS: process_status(Gid="60001 60002 60001 60001")},
    {ProcessField.STATUS: process_status(NoNewPrivs="0")},
    {ProcessField.STATUS: process_status(Seccomp="0")},
    {ProcessField.STATUS: process_status(CapBnd="0000000000000001")},
    {ProcessField.UID_MAP: b"0 60002 1\n"},
    {ProcessField.GID_MAP: b"0 60002 1\n"},
    {ProcessField.SETGROUPS: b"allow\n"},
    {ProcessField.APPARMOR_CURRENT: b"unconfined\n"},
])
def test_pid_reuse_identity_and_security_mismatches_fail_closed(changes):
    report = collect(FakeReader(changes=changes))
    assert report.state is ObservationState.FAILED
    assert report.facts is None or not report.authenticated
    assert not report.execution_authorized


@pytest.mark.parametrize("field,error,state", [
    (ProcessField.STAT, InterruptedError("read interrupted"), ObservationState.UNVERIFIED),
    (ProcessField.STATUS, OSError("read failed"), ObservationState.UNVERIFIED),
    (ProcessField.UID_MAP, ValueError("oversized read"), ObservationState.FAILED),
    (ProcessField.GID_MAP, UnicodeError("invalid encoding"), ObservationState.FAILED),
])
def test_interrupted_inconsistent_or_unavailable_reads_fail_closed(field, error, state):
    report = collect(FakeReader(changes={field: error}))
    assert report.state is state and report.facts is None


def test_exited_pidfd_is_unverified_not_a_success():
    report = collect(FakeReader(changes={"alive": False}))
    assert report.state is ObservationState.UNVERIFIED and report.facts is None


def test_malformed_kernel_data_is_failed_not_success_shaped():
    report = collect(FakeReader(changes={ProcessField.UID_MAP: b"0 x 1\n"}))
    assert report.state is ObservationState.FAILED and report.facts is None


def test_stop_during_collection_does_not_authenticate_or_authorize_late_facts():
    ctx = context()
    verifier = VerifierIdentity(ArtifactIdentity(ObjectPin(8, 93), "b" * 64), "c" * 64)
    exchange = TrustedEntryExchange(
        ctx.identity, verifier,
        (
            MappingPlan(MappingStage.INITIAL, UID_MAP, GID_MAP),
            MappingPlan(MappingStage.FINAL, UID_MAP, GID_MAP),
        ),
        ctx.request,
    )
    challenge = exchange.issue(ctx.request)
    stopped = threading.Event()

    def stop_on_read(field):
        if not stopped.is_set():
            exchange.request_stop()
            stopped.set()

    report = collect(FakeReader(hook=stop_on_read))
    assert stopped.is_set() and report.state is ObservationState.UNVERIFIED
    late = exchange.assess(challenge, object())
    assert late.stop_requested and not late.authenticated
    assert not late.execution_authorized and not late.output_publication_authorized
    with pytest.raises(ValueError, match="STOP"):
        exchange.issue(ctx.request)


def test_reader_uses_only_fixed_process_fields():
    reader = FakeReader()
    report = collect(reader)
    assert report.state is ObservationState.UNVERIFIED
    assert set(reader.reads) == {
        ProcessField.STAT, ProcessField.STATUS, ProcessField.UID_MAP, ProcessField.GID_MAP,
        ProcessField.SETGROUPS, ProcessField.APPARMOR_CURRENT,
        ProcessField.CGROUP,
    }


@pytest.mark.parametrize("sequences", [
    {ProcessField.STAT: [proc_stat(), proc_stat(start=457)]},
    {ProcessField.STATUS: [process_status(), process_status(NoNewPrivs="0")]},
    {ProcessField.UID_MAP: [b"0 60001 1\n", b"0 60002 1\n"]},
    {ProcessField.GID_MAP: [b"0 60001 1\n", b"0 60002 1\n"]},
    {ProcessField.SETGROUPS: [b"deny\n", b"allow\n"]},
    {ProcessField.CGROUP: [b"0::/worker\n", b"0::/other\n"]},
    {ProcessField.APPARMOR_CURRENT: [
        b"gvai-setup//&gvai-worker (enforce)\n", b"unconfined (enforce)\n",
    ]},
    {"namespaces_sequence": [context().expected_namespaces, ()]},
    {"cgroup_sequence": [CGROUP, ObjectPin(8, 92)]},
    {"member_sequence": [True, False]},
    {"descriptors_sequence": [DESCRIPTORS, ()]},
])
def test_inconsistent_double_observations_fail_closed(sequences):
    report = collect(FakeReader(sequences=sequences))
    assert report.state is ObservationState.FAILED
    assert report.facts is None and not report.authenticated


def test_expired_collection_is_unverified_and_discards_facts(monkeypatch):
    import gvai.linux_worker_evidence as evidence_module

    ticks = iter((100, 100 + evidence_module.MAX_WORKER_EVIDENCE_AGE_NS + 1))
    monkeypatch.setattr(evidence_module.time, "monotonic_ns", lambda: next(ticks))
    report = collect(FakeReader())
    assert report.state is ObservationState.UNVERIFIED
    assert report.facts is None and report.collected_at_ns is not None
