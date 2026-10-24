import os

import pytest

from gvai.linux_self_observation import (
    SelfObservationHarness,
    SelfObservationState,
)

SELF_PID = os.getpid()


class FakeSelfReader:
    def __init__(self, *, changes=None, sequences=None):
        self.changes = changes or {}
        self.sequences = {key: list(value) for key, value in (sequences or {}).items()}

    def _value(self, name, default):
        if name in self.sequences and self.sequences[name]:
            return self.sequences[name].pop(0)
        value = self.changes.get(name, default)
        if isinstance(value, BaseException):
            raise value
        return value

    def process_identity(self):
        return self._value("identity", (SELF_PID, 9001, "matched"))

    def process_status(self):
        return self._value("status", (
            (1000, 1000, 1000, 1000),
            (1000, 1000, 1000, 1000),
            True,
            2,
            (("CapEff", 0), ("CapPrm", 0), ("CapInh", 0), ("CapBnd", 0), ("CapAmb", 0)),
        ))

    def id_maps(self):
        return self._value("maps", (((0, 1000, 1),), ((0, 1000, 1),), "deny"))

    def apparmor_label(self):
        return self._value("apparmor", "unconfined")

    def namespace_identities(self):
        return self._value("namespaces", {
            name: (7, index + 1)
            for index, name in enumerate(("cgroup", "ipc", "mnt", "net", "pid", "uts", "user"))
        })

    def cgroup_observation(self, pid):
        assert pid == SELF_PID
        return self._value("cgroup", {
            "path_from_proc": "/",
            "device": 8,
            "inode": 1,
            "self_pid_listed": True,
        })

    def descriptor_inventory(self):
        return self._value("descriptors", ({"number": 0, "target": "pipe:[1]", "flags_octal": "0100000"},))

    def pidfd_status(self, pid):
        assert pid == SELF_PID
        return self._value("final_pidfd", "matched")


def test_self_observation_is_always_unauthenticated_and_non_authorizing():
    report = SelfObservationHarness().collect(FakeSelfReader())

    assert report.state is SelfObservationState.UNVERIFIED
    assert report.process["pid"] == SELF_PID
    assert report.process["start_ticks"] == 9001
    assert report.process["pidfd"] == "matched"
    assert report.cgroup["self_pid_listed"]
    assert report.authenticated is False
    assert report.runtime_verified is False
    assert report.execution_authorized is False
    assert report.publication_authorized is False
    assert not report


@pytest.mark.parametrize("change", [
    {"identity": (SELF_PID + 1, 9001, "matched")},
    {"status": OSError("proc status unavailable")},
    {"apparmor": OSError("AppArmor interface unavailable")},
    {"cgroup": OSError("cgroup v2 unavailable")},
    {"descriptors": OSError("fd inventory interrupted")},
    {"final_pidfd": "exited"},
])
def test_unavailable_or_inconsistent_observations_remain_unverified(change):
    report = SelfObservationHarness().collect(FakeSelfReader(changes=change))
    assert report.state is SelfObservationState.UNVERIFIED
    assert not report.authenticated
    assert not report.execution_authorized
    assert not report.publication_authorized
    assert report.errors


def test_changed_namespaces_and_descriptor_inventory_are_unverified():
    reader = FakeSelfReader(sequences={
        "namespaces": [
            {"pid": (7, 1)},
            {"pid": (7, 2)},
        ],
        "descriptors": [
            ({"number": 0, "target": "pipe:[1]", "flags_octal": "0100000"},),
            (),
        ],
    })
    report = SelfObservationHarness().collect(reader)
    assert report.checks["namespaces"] == "UNVERIFIED"
    assert report.checks["descriptor_inventory"] == "UNVERIFIED"
    assert report.state is SelfObservationState.UNVERIFIED
    assert not report.execution_authorized and not report.publication_authorized


def test_missing_pidfd_does_not_promote_self_observation():
    report = SelfObservationHarness().collect(
        FakeSelfReader(changes={"identity": (SELF_PID, 9001, "unavailable")}),
    )
    assert report.checks["pidfd"] == "UNVERIFIED"
    assert report.state is SelfObservationState.UNVERIFIED
    assert not report.runtime_verified


def test_malformed_reader_output_fails_to_unverified_without_authority():
    report = SelfObservationHarness().collect(
        FakeSelfReader(changes={"identity": ("not-a-pid", 9001, "matched")}),
    )
    assert report.checks["process_identity"] == "UNVERIFIED"
    assert "malformed identity" in " ".join(report.errors)
    assert not report.execution_authorized
    assert not report.publication_authorized


def test_changed_id_maps_are_reported_unverified():
    report = SelfObservationHarness().collect(FakeSelfReader(sequences={
        "maps": [
            (((0, 1000, 1),), ((0, 1000, 1),), "deny"),
            (((0, 1000, 1),), ((0, 1001, 1),), "deny"),
        ],
    }))
    assert report.checks["uid_gid_maps"] == "UNVERIFIED"
    assert not report.authenticated
    assert not report.execution_authorized
