"""STOP-during-active-operation, restart, stale-permit, torn-write and disconnect tests.

Interruption targets (T1-T4, see docs/stop_gate_host_readiness_v1.md) are
asserted against measurements made in this Cloud simulation only. They are NOT
evidence about Lab-01; host measurement is a separate acceptance step.
Set GVAI_LATENCY_REPORT=/path.json to save the measured values.
"""

import json
import os
import threading
import time

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import experimental_external_gate as eg
from gvai import experimental_stop_latch as sl
from test_experimental_external_gate import Deployment, LATCH, pub, signed

# Targets, seconds (simulation configuration: notice_max_age=0.6, interrupt_deadline=1.0)
T2_COOPERATIVE_INTERRUPT_AFTER_STOP_ACK = 0.5
T3_GATE_SILENCE_INTERRUPT = 0.6 + 0.5          # notice_max_age + watchdog/poll slack
T4_UNCOOPERATIVE_PROCESS_EXIT = 1.0 + 0.5 + 0.5  # deadline + cancel + slack

_MEASURED = {}


@pytest.fixture(scope="module", autouse=True)
def _save_report():
    yield
    path = os.environ.get("GVAI_LATENCY_REPORT")
    if path:
        with open(path, "w") as fh:
            json.dump(_MEASURED, fh, indent=2, sort_keys=True)


@pytest.fixture
def dep():
    d = Deployment(notice_max_age=0.6, interrupt_deadline=1.0)
    yield d
    d.close()


def start_in_flight(dep, op, seconds, n=1):
    results, started = [], []

    def run():
        svc = dep.service()
        started.append(time.monotonic())
        results.append((svc.call(op, {"seconds": seconds}), time.monotonic()))

    threads = [threading.Thread(target=run) for _ in range(n)]
    [t.start() for t in threads]
    time.sleep(0.3)
    return threads, results


def test_stop_interrupts_in_flight_cooperative_operation(dep):
    dep.arm(1)
    threads, results = start_in_flight(dep, "slow", 10)
    dep.stop(2)
    t_ack = time.monotonic()
    [t.join(10) for t in threads]
    (reply, t_done), = results
    latency = t_done - t_ack
    _MEASURED["T2_cooperative_interrupt_after_stop_ack_s"] = round(latency, 4)
    assert (reply["ok"], reply["reason"]) == (False, "interrupted_by_stop")
    assert latency <= T2_COOPERATIVE_INTERRUPT_AFTER_STOP_ACK
    assert dep.backend().audit()["executed"] == []


def test_stop_interrupts_many_concurrent_in_flight_operations(dep):
    dep.arm(1)
    threads, results = start_in_flight(dep, "slow", 10, n=8)
    dep.stop(2)
    t_ack = time.monotonic()
    [t.join(10) for t in threads]
    assert len(results) == 8
    assert all(r["reason"] == "interrupted_by_stop" for r, _ in results)
    worst = max(t for _, t in results) - t_ack
    _MEASURED["T2_worst_of_8_concurrent_s"] = round(worst, 4)
    assert worst <= T2_COOPERATIVE_INTERRUPT_AFTER_STOP_ACK
    assert dep.backend().audit()["executed"] == []


def test_new_work_after_stop_ack_is_denied_immediately(dep):
    dep.arm(1)
    dep.stop(2)
    start = time.monotonic()
    r = dep.service().call("echo", {"x": 1})
    _MEASURED["T1_new_authorization_denied_after_stop_ack_s"] = round(time.monotonic() - start, 4)
    assert not r["ok"]


def test_rearm_does_not_resurrect_in_flight_operation(dep):
    dep.arm(1)
    threads, results = start_in_flight(dep, "slow", 10)
    dep.stop(2)
    dep.arm(3)
    [t.join(10) for t in threads]
    assert results[0][0]["reason"] == "interrupted_by_stop"
    assert dep.service().call("echo", {"x": 1})["ok"]


def test_uncooperative_operation_forces_backend_exit_and_fail_closed(dep):
    dep.arm(1)
    threads, results = start_in_flight(dep, "stubborn", 30)
    dep.stop(2)
    t_ack = time.monotonic()
    dep.backend_proc.join(T4_UNCOOPERATIVE_PROCESS_EXIT + 2)
    exited = time.monotonic() - t_ack
    _MEASURED["T4_uncooperative_backend_exit_after_stop_ack_s"] = round(exited, 4)
    assert not dep.backend_proc.is_alive()
    assert dep.backend_proc.exitcode == 70
    assert exited <= T4_UNCOOPERATIVE_PROCESS_EXIT
    [t.join(10) for t in threads]
    assert results[0][0]["ok"] is False
    # Backend restarts (as systemd would) but stays denied: gate says stopped.
    dep.kill_backend()
    dep.start_backend()
    time.sleep(0.4)
    assert not dep.service().call("echo", {"x": 1})["ok"]


def test_gate_loss_cancels_in_flight_operation_within_bound(dep):
    dep.arm(1)
    threads, results = start_in_flight(dep, "slow", 10)
    dep.kill_gate()
    t_kill = time.monotonic()
    [t.join(10) for t in threads]
    (reply, t_done), = results
    latency = t_done - t_kill
    _MEASURED["T3_gate_loss_interrupt_s"] = round(latency, 4)
    assert reply["reason"] == "interrupted_by_stop"
    assert latency <= T3_GATE_SILENCE_INTERRUPT


def test_gate_restart_resumes_only_from_durable_armed_state(dep):
    dep.arm(1)
    dep.kill_gate()
    time.sleep(0.9)
    assert not dep.service().call("echo", {})["ok"]
    dep.start_gate()
    time.sleep(0.4)
    assert dep.service().call("echo", {"x": 1})["ok"]


def test_gate_restart_with_rolled_back_state_stays_denied(dep):
    dep.arm(1)
    saved = open(os.path.join(dep.state, "store.json")).read()
    dep.stop(2)
    dep.kill_gate()
    open(os.path.join(dep.state, "store.json"), "w").write(saved)
    dep.start_gate()
    time.sleep(0.9)
    assert not dep.service().call("echo", {"x": 1})["ok"]
    assert dep.control().status()["status"] == "fault"


def test_backend_restart_refuses_pre_restart_permits(dep):
    dep.arm(1)
    used = dep.gate().authorize("echo", {"x": 1})["token"]
    assert dep.backend().execute("echo", {"x": 1}, used)["ok"]
    unused = dep.gate().authorize("echo", {"x": 2})["token"]
    dep.kill_backend()
    dep.start_backend()
    time.sleep(0.4)
    b = dep.backend()
    assert b.execute("echo", {"x": 1}, used)["reason"] == "token_predates_backend_start"
    assert b.execute("echo", {"x": 2}, unused)["reason"] == "token_predates_backend_start"
    assert b.audit()["executed"] == []
    assert dep.service().call("echo", {"x": 3})["ok"]


def test_backend_without_notices_denies_after_restart(dep):
    dep.arm(1)
    dep.kill_gate()
    dep.kill_backend()
    dep.start_backend()
    r = dep.backend().execute("echo", {}, {"signature": "0" * 128})
    assert r["ok"] is False


def test_permit_from_before_stop_rearm_cycle_is_rejected(dep):
    dep.arm(1)
    tok = dep.gate().authorize("echo", {"x": 1})["token"]
    dep.stop(2)
    dep.arm(3)
    assert dep.backend().execute("echo", {"x": 1}, tok)["reason"] == "token_epoch_mismatch"


def test_service_sockets_cannot_arm_stop_or_send_notices(dep):
    g, b = dep.gate(), dep.backend()
    cmd = signed(dep.arm_key, "arm-k1", 1, "arm")  # even a perfectly valid ARM
    assert g.submit_command(cmd)["reason"] == "request_not_permitted"
    assert dep.control().status()["status"] == "stopped"
    assert b.send_notice({"type": "notice"})["reason"] == "request_not_permitted"
    assert dep.control().authorize("echo", {})["reason"] == "request_not_permitted"
    assert dep.notice_channel().execute("echo", {}, {})["reason"] == "request_not_permitted"


# ---- interrupted writes / torn state (in-process GateCore over real files)

@pytest.fixture
def keys():
    return Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()


def make_gate(tmp_path, keys):
    stop, arm = keys
    return eg.GateCore(
        str(tmp_path), LATCH, {"stop-k1": pub(stop)}, {"arm-k1": pub(arm)}, frozenset({"echo"})
    )


def arm_cmd(keys, seq):
    return signed(keys[1], "arm-k1", seq, "arm")


def test_truncated_anchor_file_denies(tmp_path, keys):
    g = make_gate(tmp_path, keys)
    assert g.handle({"type": "command", "envelope": arm_cmd(keys, 1)})["ok"]
    (tmp_path / "anchor.json").write_text('{"sequence": 1, "dig')
    g2 = make_gate(tmp_path, keys)
    assert g2.handle({"type": "status"})["status"] == "fault"
    assert not g2.authorize("echo", "0" * 64)["ok"]


@pytest.mark.parametrize("content", ['', '[]', '{"sequence": "1", "digest": "x"}', '{"sequence": -1, "digest": "x"}', "\x00\x01"])
def test_garbage_anchor_file_denies(tmp_path, keys, content):
    g = make_gate(tmp_path, keys)
    g.handle({"type": "command", "envelope": arm_cmd(keys, 1)})
    (tmp_path / "anchor.json").write_text(content)
    assert make_gate(tmp_path, keys).handle({"type": "status"})["status"] == "fault"


def test_truncated_store_file_denies(tmp_path, keys):
    g = make_gate(tmp_path, keys)
    g.handle({"type": "command", "envelope": arm_cmd(keys, 1)})
    (tmp_path / "store.json").write_text('{"version": 1, "la')
    assert make_gate(tmp_path, keys).handle({"type": "status"})["status"] == "fault"


def test_crash_between_anchor_advance_and_store_write_faults(tmp_path, keys):
    g = make_gate(tmp_path, keys)
    g.handle({"type": "command", "envelope": arm_cmd(keys, 1)})
    anchor = eg.FileTrustedAnchor(str(tmp_path / "anchor.json"))
    cur = anchor.read()
    assert anchor.compare_and_advance(cur, sl.AnchorHead(2, "a" * 64))  # crash before store.save
    g2 = make_gate(tmp_path, keys)
    assert g2.handle({"type": "status"})["status"] == "fault"


def test_leftover_tmp_files_from_crash_are_ignored(tmp_path, keys):
    (tmp_path / "anchor.json.tmp").write_text('{"sequence": 9')
    (tmp_path / "store.json.tmp").write_text("garbage")
    g = make_gate(tmp_path, keys)
    assert g.handle({"type": "command", "envelope": arm_cmd(keys, 1)})["ok"]
    assert make_gate(tmp_path, keys).authorize("echo", "0" * 64)["ok"]


def test_store_write_failure_denies_and_survives_restart_as_fault(tmp_path, keys, monkeypatch):
    g = make_gate(tmp_path, keys)

    def boom(self, envelope):
        raise OSError("disk full")

    monkeypatch.setattr(eg.FileCommandStore, "save", boom)
    r = g.handle({"type": "command", "envelope": arm_cmd(keys, 1)})
    assert r["ok"] is False and r["reason"] == "store_write_failed"
    assert not g.authorize("echo", "0" * 64)["ok"]
    monkeypatch.undo()
    assert make_gate(tmp_path, keys).handle({"type": "status"})["status"] == "fault"


def test_gate_seed_corruption_refuses_to_start(tmp_path, keys):
    make_gate(tmp_path, keys)
    (tmp_path / "gate_key.seed").write_bytes(b"short")
    with pytest.raises(ValueError):
        make_gate(tmp_path, keys)


def test_gate_seed_created_private(tmp_path, keys):
    make_gate(tmp_path, keys)
    assert oct((tmp_path / "gate_key.seed").stat().st_mode & 0o777) == "0o600"
    assert oct(tmp_path.stat().st_mode & 0o777)  # directory mode set by caller/systemd
