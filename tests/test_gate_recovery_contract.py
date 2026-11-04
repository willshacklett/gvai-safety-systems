"""I6C/I6D local recovery contracts, not physical power-loss guarantees.

Faults use real temporary gate files. No proposed journal schema is invented.
Metadata and transaction barriers are exercised without independent enforcement.
"""

import json
import os
import stat
import subprocess
import sys

import pytest

from gvai import experimental_external_gate as eg
from gvai import experimental_stop_latch as sl
from gvai import gate_transaction as gt
from test_stop_reconciliation import LATCH, Loopback, Rig, pub, signed


def require(condition, message):
    assert condition, message


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path)


def restart(rig):
    rig.gate.close()
    return eg.GateCore(
        rig.state, LATCH,
        {"stop-k1": pub(rig.stop1), "stop-k2": pub(rig.stop2)},
        {"arm-k1": pub(rig.arm)}, frozenset({"echo"}),
        clock=lambda: rig.now[0],
    )


def client(gate):
    return Loopback(eg.make_control_handler(gate, lambda notice: False))


def test_completed_arm_restart_requires_fresh_authenticated_arm(rig):
    rig.arm_to(1)
    recovered = restart(rig)
    require(
        recovered._latch.status == sl.STATUS_STOPPED,
        "restart restored recorded ARM permission instead of STOPPED",
    )
    assert recovered._latch.head.sequence == 1
    assert not recovered.authorize("echo", "0" * 64)["ok"]
    stale = signed(rig.arm, "arm-k1", 1, "arm")
    assert not recovered.handle({"type": "command", "envelope": stale})["ok"]
    forged = signed(rig.stop1, "arm-k1", 2, "arm")
    assert not recovered.handle({"type": "command", "envelope": forged})["ok"]
    fresh = signed(rig.arm, "arm-k1", 2, "arm")
    assert recovered.handle({"type": "command", "envelope": fresh})["ok"]


@pytest.mark.parametrize("kind", ["arm", "stop"])
def test_pending_store_failure_restart_fault_is_sticky(rig, monkeypatch, kind):
    rig.arm_to(1)
    envelope = (
        signed(rig.arm, "arm-k1", 2, "arm") if kind == "arm" else rig.stop(2)
    )
    real_replace = os.replace
    store = os.path.join(rig.state, "store.json")

    def replace_then_fail(src, dst, *args, **kwargs):
        result = real_replace(src, dst, *args, **kwargs)
        if dst == store:
            raise OSError("injected post-store-replacement uncertainty")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(eg.os, "replace", replace_then_fail)
        if kind == "stop":
            result = rig.client.submit_stop(envelope)
            assert not result["durable"]
            assert result["outcome"] not in ("STOP_RECORDED", "ALREADY_APPLIED")
        else:
            result = rig.gate.handle({"type": "command", "envelope": envelope})
            assert not result["ok"]
            assert not rig.gate._latch.permit().allowed
    recovered = restart(rig)
    require(
        recovered._latch.status == sl.STATUS_FAULT,
        "matching post-replacement pair erased the unresolved transaction on restart",
    )
    fresh = signed(rig.arm, "arm-k1", 3, "arm")
    assert not recovered.handle({"type": "command", "envelope": fresh})["ok"]
    reconciled = client(recovered).reconcile_stop(rig.stop(2))
    assert reconciled["verdict"] == "UNVERIFIABLE"
    assert not reconciled["stop_recorded"]


def test_post_replacement_failure_is_unknown_not_safe_to_retry(rig, monkeypatch):
    rig.arm_to(1)
    real_replace = os.replace

    def replace_then_fail(src, dst, *args, **kwargs):
        result = real_replace(src, dst, *args, **kwargs)
        if dst == os.path.join(rig.state, "store.json"):
            raise OSError("replacement visible but completion uncertain")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(eg.os, "replace", replace_then_fail)
        result = rig.client.submit_stop(rig.stop(2))
    assert not result["durable"]
    assert not rig.gate._latch.permit().allowed
    require(result["outcome"] == "UNKNOWN", "ambiguous STOP classified as NOT_DURABLE")


@pytest.mark.parametrize("kind", ["arm", "stop"])
def test_missing_transaction_metadata_denies_legacy_state(rig, kind):
    # Construct only the original signed anchor/store pair: explicit legacy state.
    envelope = (
        signed(rig.arm, "arm-k1", 1, "arm") if kind == "arm" else rig.stop(1)
    )
    command = sl.parse_command(envelope)
    with open(os.path.join(rig.state, "anchor.json"), "w") as stream:
        json.dump({"sequence": 1, "digest": command.digest()}, stream)
    with open(os.path.join(rig.state, "store.json"), "w") as stream:
        json.dump(envelope, stream)
    os.unlink(os.path.join(rig.state, "transaction.json"))
    recovered = restart(rig)
    require(
        recovered._latch.status == sl.STATUS_FAULT,
        "legacy pair accepted without transaction metadata or offline migration",
    )
    assert not recovered._latch.permit().allowed
    fresh = signed(rig.arm, "arm-k1", 2, "arm")
    assert not recovered.handle({"type": "command", "envelope": fresh})["ok"]


@pytest.mark.parametrize("record", ["anchor.json", "store.json"])
def test_corrupt_existing_record_fault_denies_arm_and_reconciliation(rig, record):
    rig.arm_to(1)
    with open(os.path.join(rig.state, record), "w") as stream:
        stream.write('{"incomplete":')
    recovered = restart(rig)
    assert recovered._latch.status == sl.STATUS_FAULT
    fresh = signed(rig.arm, "arm-k1", 2, "arm")
    assert not recovered.handle({"type": "command", "envelope": fresh})["ok"]
    result = client(recovered).reconcile_stop(rig.stop(2))
    assert result["verdict"] == "UNVERIFIABLE"
    assert not result["stop_recorded"]


def test_current_matching_stop_reconciles_but_never_claims_backend_halt(rig):
    # Local confirmation remains distinct from backend termination evidence.
    result = rig.client.submit_stop(rig.stop(1))
    assert result["outcome"] == "STOP_RECORDED"
    recovered = restart(rig)
    result = client(recovered).reconcile_stop(rig.stop(1))
    assert recovered._latch.status == sl.STATUS_STOPPED
    assert result["verdict"] == "EXACT_APPLIED"
    assert result["head_digest"] == result["submitted_digest"]
    assert result["backend_halt"] == "UNVERIFIED"


def test_stop_ack_requires_file_and_directory_barriers(rig, monkeypatch):
    rig.arm_to(1)
    synced = []
    real_sync = os.fsync

    def observe(fd):
        synced.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
        return real_sync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(eg.os, "fsync", observe)
        result = rig.client.submit_stop(rig.stop(2))
    require(
        synced.count("directory") >= 2,
        "STOP acknowledgement lacks anchor/store directory synchronization",
    )
    assert result["outcome"] == "STOP_RECORDED" and result["durable"]
    recovered = restart(rig)
    result = client(recovered).reconcile_stop(rig.stop(2))
    assert result["verdict"] == "EXACT_APPLIED" and result["stop_recorded"]
    assert result["head_digest"] == sl.parse_command(rig.stop(2)).digest()
    assert result["backend_halt"] == "UNVERIFIED"


def test_directory_sync_failure_never_confirms_stop(rig, monkeypatch):
    rig.arm_to(1)
    reached = []
    real_sync = os.fsync

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            reached.append(True)
            raise OSError("injected directory barrier failure")
        return real_sync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(eg.os, "fsync", fail_directory)
        result = rig.client.submit_stop(rig.stop(2))
    require(reached, "no directory barrier exists to fault-inject")
    assert result["outcome"] == "UNKNOWN" and not result["durable"]
    assert not rig.gate._latch.permit().allowed
    recovered = restart(rig)
    assert recovered._latch.status == sl.STATUS_FAULT
    assert not client(recovered).reconcile_stop(rig.stop(2))["stop_recorded"]


def test_ambiguous_intent_cleanup_requires_faulted_recovery(rig, monkeypatch):
    rig.arm_to(1)
    reached = []
    real_unlink = os.unlink

    def unlink_then_fail(path, *args, **kwargs):
        result = real_unlink(path, *args, **kwargs)
        reached.append(path)
        raise OSError("injected post-intent-unlink uncertainty")

    with monkeypatch.context() as patch:
        patch.setattr(eg.os, "unlink", unlink_then_fail)
        result = rig.client.submit_stop(rig.stop(2))
    require(reached, "no transaction-intent cleanup exists to fault-inject")
    assert result["outcome"] == "UNKNOWN" and not result["durable"]
    assert not rig.gate._latch.permit().allowed
    # Restart must deny; a later confirmation cannot retroactively change UNKNOWN.
    assert not restart(rig)._latch.permit().allowed


def test_corrupt_transaction_metadata_cannot_be_ignored(rig):
    rig.arm_to(1)
    metadata = {"transaction.json"}
    require(metadata, "gate emits no transaction metadata to validate on recovery")
    for name in metadata:
        path = os.path.join(rig.state, name)
        if os.path.isfile(path):
            with open(path, "wb") as stream:
                stream.write(b'{"truncated":')
    recovered = restart(rig)
    assert recovered._latch.status == sl.STATUS_FAULT
    assert not recovered._latch.permit().allowed


PHASES = [
    "before_intent", "intent_written", "before_intent_sync",
    "intent_file_synced", "intent_durable",
    *(name + ":" + phase for name in ("anchor.json", "store.json", "transaction.json")
      for phase in ("written", "before_file_sync", "file_synced", "before_replace",
                    "replaced", "before_directory_sync", "directory_synced",
                    "before_readback", "read_back")),
    "before_cleanup", "intent_removed", "cleanup_synced", "before_ack",
]
CLEAN_CRASH_PHASES = {"before_intent", "intent_removed", "cleanup_synced", "before_ack"}


@pytest.mark.parametrize("kind", ["arm", "stop"])
@pytest.mark.parametrize("phase", PHASES)
def test_transaction_barrier_failure_is_unknown_and_denied(rig, kind, phase):
    rig.arm_to(1)
    envelope = signed(
        rig.arm if kind == "arm" else rig.stop1,
        "arm-k1" if kind == "arm" else "stop-k1", 2, kind,
    )
    reached = []

    def fail(name):
        if name == phase:
            reached.append(name)
            raise OSError("injected transaction barrier")

    rig.gate._transaction.phase = fail
    result = rig.gate.handle({"type": "command", "envelope": envelope})
    assert reached == [phase]
    assert result["ok"] is False and result["reason"] == "persistence_unknown"
    assert rig.gate._latch.status == sl.STATUS_FAULT
    assert not rig.gate.authorize("echo", "0" * 64)["ok"]
    recovered = restart(rig)
    assert recovered._latch.status == (
        sl.STATUS_STOPPED if phase in CLEAN_CRASH_PHASES else sl.STATUS_FAULT
    )
    assert not recovered._latch.permit().allowed
    if kind == "stop" and phase not in CLEAN_CRASH_PHASES:
        assert not client(recovered).reconcile_stop(envelope)["stop_recorded"]


@pytest.mark.parametrize("kind", ["arm", "stop"])
@pytest.mark.parametrize("phase", PHASES)
def test_process_exit_at_transaction_barriers(rig, kind, phase):
    rig.arm_to(1)
    envelope = signed(
        rig.arm if kind == "arm" else rig.stop1,
        "arm-k1" if kind == "arm" else "stop-k1", 2, kind,
    )
    rig.gate.close()
    script = """
import json, os, sys
from gvai.experimental_external_gate import GateCore
directory, latch, stop, arm, envelope, phase = sys.argv[1:]
gate = GateCore(directory, latch, {"stop-k1": bytes.fromhex(stop)},
                {"arm-k1": bytes.fromhex(arm)}, frozenset({"echo"}))
def exit_at(name):
    if name == phase:
        os._exit(73)
gate._transaction.phase = exit_at
gate.handle({"type": "command", "envelope": json.loads(envelope)})
raise SystemExit(74)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, rig.state, LATCH, pub(rig.stop1).hex(),
         pub(rig.arm).hex(), json.dumps(envelope), phase],
        capture_output=True, timeout=10,
    )
    assert result.returncode == 73, result.stderr.decode()
    recovered = restart(rig)
    assert recovered._latch.status == (
        sl.STATUS_STOPPED if phase in CLEAN_CRASH_PHASES else sl.STATUS_FAULT
    )
    assert not recovered._latch.permit().allowed
    reconciled = client(recovered).reconcile_stop(rig.stop(2))
    confirmed = kind == "stop" and phase in CLEAN_CRASH_PHASES - {"before_intent"}
    assert reconciled["stop_recorded"] is confirmed
    assert reconciled["backend_halt"] == "UNVERIFIED"


def test_exclusive_writer_rejects_second_session(rig):
    with pytest.raises(ValueError, match="gate_writer_busy"):
        eg.GateCore(
            rig.state, LATCH, {"stop-k1": pub(rig.stop1)}, {"arm-k1": pub(rig.arm)},
            frozenset({"echo"}),
        )
    assert rig.gate._transaction.load()


@pytest.mark.parametrize("content", [b"", b"[]", b'{"revision":true}', b"x" * 16385])
def test_invalid_receipt_denies_startup(rig, content):
    with open(os.path.join(rig.state, "transaction.json"), "wb") as stream:
        stream.write(content)
    recovered = restart(rig)
    assert recovered._latch.status == sl.STATUS_FAULT
    assert not recovered.authorize("echo", "0" * 64)["ok"]


def test_offline_provisioning_never_overwrites_legacy_or_existing_state(rig, tmp_path):
    with pytest.raises(FileExistsError):
        eg.GateTransaction.provision(rig.state, LATCH)
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "store.json").write_text("legacy")
    with pytest.raises(FileExistsError):
        eg.GateTransaction.provision(str(legacy), LATCH)
    assert (legacy / "store.json").read_text() == "legacy"


@pytest.mark.parametrize("record", ["anchor.json", "store.json", "transaction.json"])
@pytest.mark.parametrize("substitution", ["symlink", "hardlink"])
def test_record_substitution_denies_recovery(rig, record, substitution, tmp_path):
    rig.arm_to(1)
    path = os.path.join(rig.state, record)
    target = tmp_path / "substituted"
    with open(path, "rb") as stream:
        target.write_bytes(stream.read())
    target.chmod(0o600)
    os.unlink(path)
    if substitution == "symlink":
        os.symlink(target, path)
    else:
        os.link(target, path)
    recovered = restart(rig)
    assert recovered._latch.status == sl.STATUS_FAULT
    assert not recovered._latch.permit().allowed


@pytest.mark.parametrize("record", ["anchor.json", "store.json", "transaction.json"])
def test_exact_readback_rejects_changed_contents_before_ack(rig, record):
    rig.arm_to(1)

    def corrupt(phase):
        if phase == record + ":before_readback":
            with open(os.path.join(rig.state, record), "wb") as stream:
                stream.write(b"corrupted")

    rig.gate._transaction.phase = corrupt
    result = rig.client.submit_stop(rig.stop(2))
    assert result["outcome"] == "UNKNOWN" and not result["durable"]
    assert not rig.gate._latch.permit().allowed
    assert restart(rig)._latch.status == sl.STATUS_FAULT


@pytest.mark.parametrize("field,value", [
    ("version", True), ("version", 2), ("revision", True), ("revision", -1),
    ("revision", 2**53 + 1), ("latch_id", "another-latch"),
    ("anchor_hash", "00" * 32), ("store_hash", "00" * 32),
    ("previous", []), ("command", {"forged": True}),
])
def test_receipt_field_validation_is_strict(rig, field, value):
    rig.arm_to(1)
    path = os.path.join(rig.state, gt.RECEIPT)
    with open(path, "rb") as stream:
        receipt = json.load(stream)
    receipt[field] = value
    with open(path, "wb") as stream:
        stream.write(gt.canonical(receipt))
    assert restart(rig)._latch.status == sl.STATUS_FAULT


def test_receipt_duplicate_fields_are_rejected(rig):
    path = os.path.join(rig.state, gt.RECEIPT)
    with open(path, "rb") as stream:
        raw = stream.read()
    with open(path, "wb") as stream:
        stream.write(b'{"version":1,' + raw[1:])
    assert restart(rig)._latch.status == sl.STATUS_FAULT


def test_missing_seed_never_creates_a_replacement(rig):
    rig.gate.close()
    path = os.path.join(rig.state, "gate_key.seed")
    os.unlink(path)
    with pytest.raises(FileNotFoundError):
        restart(rig)
    assert not os.path.exists(path)
