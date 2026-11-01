import json
import multiprocessing
import os
import shutil
import tempfile
import threading
import time

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import experimental_external_gate as eg
from gvai import experimental_stop_latch as sl

LATCH = "latch-1"
CTX = multiprocessing.get_context("spawn")


def pub(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def signed(key, key_id, seq, kind, latch_id=LATCH):
    sig = key.sign(sl.signing_bytes(latch_id, seq, kind, key_id))
    return {
        "version": 1, "latch_id": latch_id, "sequence": seq,
        "command_type": kind, "key_id": key_id, "signature": sig.hex(),
    }


class Deployment:
    """Gate and backend as real child processes (simulated separation only)."""

    def __init__(self, token_ttl=5.0, notice_max_age=3.0, with_gate=True, with_backend=True):
        self.dir = tempfile.mkdtemp(prefix="gg")
        self.stop_key, self.arm_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.token_ttl, self.notice_max_age = token_ttl, notice_max_age
        self.gate_sock = os.path.join(self.dir, "g.sock")
        self.backend_sock = os.path.join(self.dir, "b.sock")
        self.state = os.path.join(self.dir, "state")
        self.procs, self.gate_proc, self.gate_pub = [], None, None
        self.clients = []
        if with_gate:
            self.start_gate()
        if with_backend:
            self.start_backend()

    def _spawn(self, target, config):
        parent, child = CTX.Pipe()
        p = CTX.Process(target=target, args=(config, child), daemon=True)
        p.start()
        assert parent.poll(15), "child did not start"
        info = json.loads(parent.recv_bytes())
        self.procs.append(p)
        return p, info

    def start_gate(self):
        cfg = {
            "state_dir": self.state, "latch_id": LATCH, "socket": self.gate_sock,
            "backend_socket": self.backend_sock, "heartbeat_interval": 0.1,
            "stop_keys": {"stop-k1": pub(self.stop_key).hex()},
            "arm_keys": {"arm-k1": pub(self.arm_key).hex()},
            "operations": ["echo", "charge"], "token_ttl": self.token_ttl,
        }
        self.gate_proc, info = self._spawn(eg.gate_process_main, cfg)
        self.gate_pub = info["gate_public_key"]

    def kill_gate(self):
        self.gate_proc.kill()
        self.gate_proc.join(5)
        if os.path.exists(self.gate_sock):
            os.unlink(self.gate_sock)

    def start_backend(self):
        cfg = {
            "gate_public_key": self.gate_pub, "latch_id": LATCH,
            "socket": self.backend_sock, "notice_max_age": self.notice_max_age,
        }
        self.backend_proc, _ = self._spawn(eg.backend_process_main, cfg)

    def gate(self):
        c = eg.GateClient(self.gate_sock)
        self.clients.append(c)
        return c

    def backend(self):
        c = eg.BackendClient(self.backend_sock)
        self.clients.append(c)
        return c

    def service(self):
        return eg.GatedService(self.gate(), self.backend())

    def arm(self, seq):
        r = self.gate().submit_command(signed(self.arm_key, "arm-k1", seq, "arm"))
        assert r["ok"], r
        time.sleep(0.05)

    def stop(self, seq):
        r = self.gate().submit_command(signed(self.stop_key, "stop-k1", seq, "stop"))
        assert r["ok"], r

    def close(self):
        for c in self.clients:
            c.close()
        for p in self.procs:
            if p.is_alive():
                p.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


@pytest.fixture
def dep():
    d = Deployment()
    yield d
    d.close()


def wait_denied(svc, reason=None, tries=40):
    for _ in range(tries):
        r = svc.call("echo", {"x": 1})
        if not r["ok"] and (reason is None or r["reason"] == reason):
            return r
        time.sleep(0.1)
    raise AssertionError(r)


def test_declared_models_are_simulation_only():
    assert eg.SEPARATION_MODEL == "simulated_process_separation_same_uid"
    assert eg.OS_ENFORCED_ISOLATION_IMPLEMENTED is False


def test_gate_runs_in_separate_process(dep):
    assert dep.gate_proc.pid != os.getpid() and dep.backend_proc.pid != os.getpid()
    assert dep.gate_proc.pid != dep.backend_proc.pid


def test_fresh_deployment_denies(dep):
    svc = dep.service()
    r = svc.call("echo", {"x": 1})
    assert (r["ok"], r["reason"]) == (False, "latched_stop")
    assert dep.backend().audit()["executed"] == []


def test_armed_operation_executes_through_gate(dep):
    dep.arm(1)
    r = dep.service().call("charge", {"amount": 5})
    assert r == {"ok": True, "result": {"charged": 5}}
    assert dep.backend().audit()["executed"] == [["charge", {"amount": 5}]]


def test_stop_denies_and_invalidates_held_token(dep):
    dep.arm(1)
    gate, backend = dep.gate(), dep.backend()
    permit = gate.authorize("echo", {"x": 1})
    assert permit["ok"]
    dep.stop(2)
    r = backend.execute("echo", {"x": 1}, permit["token"])
    assert (r["ok"], r["reason"]) == (False, "gate_not_armed")
    assert not dep.service().call("echo", {"x": 1})["ok"]
    assert dep.backend().audit()["executed"] == []


def test_omitting_verifier_call_cannot_bypass(dep):
    dep.arm(1)
    b = dep.backend()
    assert b.execute("echo", {"x": 1}, None)["reason"] == "malformed_request"
    assert b.execute("echo", {"x": 1}, {})["reason"] == "token_authentication_failed"
    dep.stop(2)
    assert not b.execute("echo", {"x": 1}, {})["ok"]
    assert b.audit()["executed"] == []


def test_forged_token_from_compromised_service_denied(dep):
    dep.arm(1)
    good = dep.gate().authorize("charge", {"amount": 1})["token"]
    forged = {k: v for k, v in good.items() if k != "signature"}
    forged["signature"] = Ed25519PrivateKey.generate().sign(b"x").hex()
    b = dep.backend()
    assert b.execute("charge", {"amount": 1}, forged)["reason"] == "token_authentication_failed"
    tampered = dict(good, args_digest="0" * 64)
    assert b.execute("charge", {"amount": 1}, tampered)["reason"] == "token_authentication_failed"
    assert b.execute("charge", {"amount": 999}, good)["reason"] == "token_mismatch"
    assert b.execute("echo", {"amount": 1}, good)["reason"] == "token_mismatch"
    assert b.audit()["executed"] == []


def test_token_is_single_use(dep):
    dep.arm(1)
    tok = dep.gate().authorize("echo", {"x": 1})["token"]
    b = dep.backend()
    assert b.execute("echo", {"x": 1}, tok)["ok"]
    assert b.execute("echo", {"x": 1}, tok)["reason"] == "token_replayed"


def test_expired_token_denied():
    d = Deployment(token_ttl=0.3)
    try:
        d.arm(1)
        tok = d.gate().authorize("echo", {"x": 1})["token"]
        time.sleep(0.6)
        assert d.backend().execute("echo", {"x": 1}, tok)["reason"] == "token_expired"
    finally:
        d.close()


def test_compromised_service_cannot_arm_or_stop_with_own_keys(dep):
    attacker = Ed25519PrivateKey.generate()
    g = dep.gate()
    for kid in ("arm-k1", "stop-k1", "attacker"):
        r = g.submit_command(signed(attacker, kid, 1, "arm"))
        assert (r["ok"], r["reason"]) == (False, "authentication_failed")
    assert not dep.service().call("echo", {})["ok"]
    dep.arm(1)
    r = g.submit_command(signed(attacker, "stop-k1", 2, "stop"))
    assert not r["ok"]
    assert dep.service().call("echo", {"x": 1})["ok"]


def test_stop_key_cannot_arm_and_arm_key_cannot_stop(dep):
    g = dep.gate()
    assert not g.submit_command(signed(dep.stop_key, "stop-k1", 1, "arm"))["ok"]
    assert not g.submit_command(signed(dep.stop_key, "arm-k1", 1, "arm"))["ok"]
    dep.arm(1)
    assert not g.submit_command(signed(dep.arm_key, "arm-k1", 2, "stop"))["ok"]
    assert dep.service().call("echo", {"x": 1})["ok"]


def test_replayed_commands_rejected_after_restart(dep):
    arm1 = signed(dep.arm_key, "arm-k1", 1, "arm")
    assert dep.gate().submit_command(arm1)["ok"]
    dep.stop(2)
    dep.kill_gate()
    dep.start_gate()
    g = dep.gate()
    assert g.submit_command(arm1)["reason"] == "stale_or_replayed"
    assert not dep.service().call("echo", {})["ok"]


def test_arm_key_cannot_mint_permits_or_notices(dep):
    dep.arm(1)
    good = dep.gate().authorize("echo", {"x": 1})["token"]
    body = {k: v for k, v in good.items() if k != "signature"}
    body["signature"] = dep.arm_key.sign(eg._PERMIT_DOMAIN + eg._canon(body)).hex()
    assert dep.backend().execute("echo", {"x": 1}, body)["reason"] == "token_authentication_failed"


def test_forged_notice_cannot_reopen_backend(dep):
    dep.arm(1)
    dep.stop(2)
    atk = Ed25519PrivateKey.generate()
    notice = {
        "type": "notice", "latch_id": LATCH, "key_id": "gate-x", "boot_id": "ab",
        "counter": 10**6, "status": "armed", "allowed": True, "sequence": 99, "digest": "0" * 64,
    }
    notice["signature"] = atk.sign(b"x").hex()
    assert dep.backend().send_notice(notice)["reason"] == "notice_authentication_failed"
    assert not dep.service().call("echo", {"x": 1})["ok"]


def test_gate_restart_preserves_state_and_key(dep):
    dep.arm(1)
    pub_before = dep.gate_pub
    dep.kill_gate()
    # gate down: new permits impossible
    assert dep.gate_sock and not os.path.exists(dep.gate_sock)
    with pytest.raises(Exception):
        eg.GateClient(dep.gate_sock)
    dep.start_gate()
    assert dep.gate_pub == pub_before
    time.sleep(0.4)
    assert dep.service().call("echo", {"x": 1})["ok"]


def test_stop_survives_gate_restart(dep):
    dep.arm(1)
    dep.stop(2)
    dep.kill_gate()
    dep.start_gate()
    time.sleep(0.4)
    assert not dep.service().call("echo", {"x": 1})["ok"]
    assert dep.gate().status()["status"] == "stopped"


def test_anchor_rollback_between_restarts_faults(dep):
    dep.arm(1)
    dep.stop(2)
    dep.arm(3)
    dep.kill_gate()
    os.unlink(os.path.join(dep.state, "anchor.json"))  # attacker rewinds anchor
    dep.start_gate()
    time.sleep(0.4)
    assert dep.gate().status()["status"] == "fault"
    assert not dep.service().call("echo", {"x": 1})["ok"]
    assert not dep.gate().submit_command(signed(dep.arm_key, "arm-k1", 1, "arm"))["ok"]


def test_store_rollback_between_restarts_faults(dep):
    dep.arm(1)
    saved = open(os.path.join(dep.state, "store.json")).read()
    dep.stop(2)
    dep.arm(3)
    dep.kill_gate()
    open(os.path.join(dep.state, "store.json"), "w").write(saved)
    dep.start_gate()
    time.sleep(0.3)
    assert dep.gate().status()["reason"] == "store_rollback_detected"


def test_live_anchor_tamper_is_detected_not_prevented(dep):
    # Same-UID simulation: the file CAN be written; the gate detects it and denies.
    dep.arm(1)
    dep.stop(2)
    dep.arm(3)
    with open(os.path.join(dep.state, "anchor.json"), "w") as fh:
        json.dump({"sequence": 1, "digest": "0" * 64}, fh)
    r = dep.service().call("echo", {"x": 1})
    assert not r["ok"]
    assert dep.gate().status()["status"] == "fault"


def test_gate_down_means_deny(dep):
    dep.arm(1)
    svc = dep.service()
    assert svc.call("echo", {"x": 1})["ok"]
    dep.kill_gate()
    assert svc.call("echo", {"x": 1})["reason"] == "communication_failure"


def test_backend_denies_when_gate_notices_go_stale():
    d = Deployment(notice_max_age=0.6)
    try:
        d.arm(1)
        tok = d.gate().authorize("echo", {"x": 1})["token"]
        d.kill_gate()
        time.sleep(1.0)
        assert d.backend().execute("echo", {"x": 1}, tok)["reason"] == "gate_notice_stale"
    finally:
        d.close()


def test_backend_without_gate_denies():
    d = Deployment(with_gate=False, with_backend=False)
    try:
        d.start_gate()
        d.kill_gate()
        d.start_backend()
        assert d.backend().execute("echo", {}, {})["ok"] is False
    finally:
        d.close()


def test_oversized_message_is_deny(dep):
    g = dep.gate()
    r = g.request({"type": "command", "envelope": {"pad": "x" * (eg.MAX_MESSAGE_BYTES * 2)}})
    assert r["ok"] is False
    assert dep.gate().status()["ok"]  # gate still serving


def test_malformed_requests_denied(dep):
    g = dep.gate()
    for bad in ({}, {"type": "nope"}, {"type": "authorize", "operation": 5},
                {"type": "authorize", "operation": "rm", "args_digest": "0" * 64},
                {"type": "command", "envelope": "x"}):
        assert g.request(bad)["ok"] is False
    dep.arm(1)
    assert g.request({"type": "authorize", "operation": "rm", "args_digest": "0" * 64})["reason"] == (
        "operation_not_authorized"
    )


def test_concurrent_authorize_when_armed_all_unique_and_execute(dep):
    dep.arm(1)
    results = []

    def worker(i):
        results.append(dep.service().call("echo", {"i": i}))

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(24)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert all(r["ok"] for r in results)
    assert len(dep.backend().audit()["executed"]) == 24


def test_stop_during_concurrent_load_leaves_no_post_stop_execution(dep):
    dep.arm(1)
    stop_done = threading.Event()
    post_stop = []

    def worker():
        svc = dep.service()
        n_after = 0
        while n_after < 5:
            after = stop_done.is_set()
            r = svc.call("echo", {"t": time.time()})
            if after:
                post_stop.append(r)
                n_after += 1

    ts = [threading.Thread(target=worker) for _ in range(6)]
    [t.start() for t in ts]
    time.sleep(0.1)
    dep.stop(2)
    stop_done.set()
    [t.join() for t in ts]
    assert post_stop and not any(r["ok"] for r in post_stop)


def test_concurrent_conflicting_arm_commands_single_winner(dep):
    dep.arm(1)
    dep.stop(2)
    res = []
    cmd = signed(dep.arm_key, "arm-k1", 3, "arm")
    ts = [threading.Thread(target=lambda: res.append(dep.gate().submit_command(cmd))) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(r["ok"] for r in res) == 1


def test_gated_service_holds_no_key_material(dep):
    svc = dep.service()
    names = " ".join(vars(svc)).lower() + " ".join(vars(svc._gate)).lower()
    assert "key" not in names and "seed" not in names and "anchor" not in names


# ---- in-process core tests (no process separation claimed)

@pytest.fixture
def cores(tmp_path):
    stop, arm = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    now = [1000.0]
    mono = [0.0]
    gate = eg.GateCore(
        str(tmp_path / "s"), LATCH, {"stop-k1": pub(stop)}, {"arm-k1": pub(arm)},
        frozenset({"echo"}), clock=lambda: now[0],
    )
    backend = eg.BackendCore(
        gate.gate_public_key, LATCH, {"echo": lambda a: a},
        notice_max_age=3.0, clock=lambda: now[0], monotonic=lambda: mono[0],
    )
    return gate, backend, stop, arm, now, mono


def test_backend_rejects_replayed_and_rolled_back_notices(cores):
    gate, backend, stop, arm, *_ = cores
    n1 = gate.notice()
    assert backend.apply_notice(n1)["ok"]
    assert backend.apply_notice(n1)["reason"] == "notice_replayed"
    gate.handle({"type": "command", "envelope": signed(arm, "arm-k1", 1, "arm")})
    n2 = gate.notice()
    assert backend.apply_notice(n2)["ok"]
    assert backend.apply_notice(n1)["reason"] in ("notice_replayed", "notice_rollback")


def test_backend_rejects_old_boot_notice_after_gate_restart(cores, tmp_path):
    gate, backend, stop, arm, *_ = cores
    old = gate.notice()
    assert backend.apply_notice(old)["ok"]
    gate2 = eg.GateCore(
        str(tmp_path / "s"), LATCH, {"stop-k1": pub(stop)}, {"arm-k1": pub(arm)}, frozenset({"echo"})
    )
    assert backend.apply_notice(gate2.notice())["ok"]
    assert backend.apply_notice(old)["reason"] == "notice_replayed"


def test_backend_denies_on_clock_staleness_and_expiry(cores):
    gate, backend, stop, arm, now, mono = cores
    gate.handle({"type": "command", "envelope": signed(arm, "arm-k1", 1, "arm")})
    backend.apply_notice(gate.notice())
    args = {"a": 1}
    tok = gate.authorize("echo", eg.args_digest(args))["token"]
    now[0] += 6
    assert backend.execute("echo", args, tok)["reason"] == "token_expired"
    tok = gate.authorize("echo", eg.args_digest(args))["token"]
    mono[0] += 4
    assert backend.execute("echo", args, tok)["reason"] == "gate_notice_stale"


def test_backend_core_never_raises_on_garbage(cores):
    _, backend, *_ = cores
    for m in (None, 1, [], {"type": "execute"}, {"type": "notice"}, {"type": "execute", "operation": "echo", "args": {}, "token": {"signature": 5}}):
        assert backend.handle(m)["ok"] is False


def test_gate_key_not_shared_with_command_keys(cores):
    gate, _, stop, arm, *_ = cores
    assert gate.gate_public_key not in (pub(stop), pub(arm))
    with pytest.raises(sl.StopLatchConfigError):
        sl.StopLatchKeyring({"a": gate.gate_public_key}, {"b": pub(arm)}, [gate.gate_public_key])
