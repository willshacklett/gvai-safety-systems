"""STOP command reconciliation V1: deterministic fault injection, no sockets, no sleeps.

The loopback client calls the real GateCore control handler in-process and can
drop the request before it is applied or drop the reply after it is applied.
This proves gate logic only; it says nothing about real socket timing or about
whether a backend process actually halted.
"""

import json
import os
import threading

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import experimental_external_gate as eg
from gvai import experimental_stop_latch as sl

LATCH = "latch-1"
COMM = {"ok": False, "reason": "communication_failure"}


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


class Loopback(eg.GateClient):
    """GateClient whose transport is a fault-injectable in-process call."""

    def __init__(self, handler):
        self.handler = handler
        self.mode = "ok"  # ok | drop_before | drop_after | garbage
        self.delivered = 0

    def request(self, message):
        if self.mode == "drop_before":
            return dict(COMM)
        wire = json.loads(json.dumps(message))
        reply = self.handler(wire)
        self.delivered += 1
        if self.mode == "drop_after":
            return dict(COMM)
        if self.mode == "garbage":
            return {"ok": False, "reason": "bad_reply"}
        return json.loads(json.dumps(reply))


class Rig:
    def __init__(self, tmp_path):
        self.stop1, self.stop2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        self.arm = Ed25519PrivateKey.generate()
        self.now, self.mono = [1000.0], [0.0]
        self.state = str(tmp_path / "s")
        self.gate = eg.GateCore(
            self.state, LATCH, {"stop-k1": pub(self.stop1), "stop-k2": pub(self.stop2)},
            {"arm-k1": pub(self.arm)}, frozenset({"echo"}), clock=lambda: self.now[0],
        )
        self.backend = eg.BackendCore(
            self.gate.gate_public_key, LATCH, {"echo": lambda a, c: a},
            notice_max_age=3.0, clock=lambda: self.now[0], monotonic=lambda: self.mono[0],
        )
        self.pushes = []
        self.deliver_notices = True
        self.ack = True
        self.client = Loopback(eg.make_control_handler(self.gate, self._push))

    def _push(self, notice=None):
        self.pushes.append(notice)
        if self.deliver_notices and notice is not None:
            self.backend.apply_notice(notice)
        return self.ack

    def arm_to(self, seq=1):
        r = self.gate.handle({"type": "command", "envelope": signed(self.arm, "arm-k1", seq, "arm")})
        assert r["ok"]
        self.backend.apply_notice(self.gate.notice())

    def stop(self, seq, key="stop1", kid="stop-k1"):
        return signed(getattr(self, key), kid, seq, "stop")


@pytest.fixture
def rig(tmp_path):
    return Rig(tmp_path)


# ---- authentication of the query

def test_reconcile_requires_valid_signed_stop(rig):
    rig.arm_to(1)
    attacker = Ed25519PrivateKey.generate()
    cases = [
        signed(attacker, "stop-k1", 2, "stop"),
        signed(rig.stop1, "stop-k1", 2, "stop", latch_id="other-latch"),
        signed(rig.arm, "arm-k1", 2, "arm"),
        signed(rig.arm, "arm-k1", 2, "stop"),
        {"version": 1},
        None,
        "x",
    ]
    for env in cases:
        r = rig.client.reconcile_stop(env) if isinstance(env, dict) else rig.gate.reconcile(env)
        assert r["ok"] is False
        assert r["verdict"] == "REJECTED"
        assert r.get("head_sequence") is None and r.get("head_digest") is None
        assert r["stop_recorded"] is False


def test_service_socket_cannot_reconcile(rig):
    rig.arm_to(1)
    r = rig.gate.handle(
        {"type": "reconcile", "envelope": rig.stop(2)}, eg.SERVICE_GATE_REQUESTS
    )
    assert r == {"ok": False, "reason": "request_not_permitted"}
    assert "head_sequence" not in rig.gate.handle({"type": "status"}, eg.SERVICE_GATE_REQUESTS)


def test_reconcile_is_read_only(rig):
    rig.arm_to(1)
    before = (rig.gate._latch.head, rig.gate._latch.status, len(rig.pushes))
    for _ in range(3):
        assert rig.client.reconcile_stop(rig.stop(2))["verdict"] == "NOT_APPLIED"
    assert (rig.gate._latch.head, rig.gate._latch.status, len(rig.pushes)) == before
    assert rig.gate.authorize("echo", "0" * 64)["ok"]


# ---- timeout before / after application

def test_timeout_before_application_is_unknown_and_changes_nothing(rig):
    rig.arm_to(1)
    rig.client.mode = "drop_before"
    out = rig.client.submit_stop(rig.stop(2))
    assert out["outcome"] == "UNKNOWN" and out["durable"] is False
    assert out["backend_halt"] == "UNVERIFIED"
    assert rig.client.delivered == 0
    rig.client.mode = "ok"
    assert rig.client.reconcile_stop(rig.stop(2))["verdict"] == "NOT_APPLIED"
    assert rig.gate.authorize("echo", "0" * 64)["ok"]  # STOP genuinely not applied
    out = rig.client.submit_stop(rig.stop(2))
    assert out["outcome"] == "STOP_RECORDED" and out["durable"] is True


def test_timeout_after_application_is_unknown_then_reconciles_exact(rig):
    rig.arm_to(1)
    rig.client.mode = "drop_after"
    out = rig.client.submit_stop(rig.stop(2))
    assert out["outcome"] == "UNKNOWN" and out["durable"] is False
    assert rig.client.delivered == 1
    rig.client.mode = "ok"
    r = rig.client.reconcile_stop(rig.stop(2))
    assert r["verdict"] == "EXACT_APPLIED" and r["stop_recorded"] is True
    assert r["head_sequence"] == 2 and r["head_digest"] == r["submitted_digest"]
    assert r["backend_halt"] == "UNVERIFIED"
    assert not rig.gate.authorize("echo", "0" * 64)["ok"]


@pytest.mark.parametrize("mode", ["drop_before", "drop_after", "garbage"])
def test_transport_failures_never_yield_affirmative_ack(rig, mode):
    rig.arm_to(1)
    rig.client.mode = mode
    out = rig.client.submit_stop(rig.stop(2))
    assert out["outcome"] != "STOP_RECORDED" and out["outcome"] != "ALREADY_APPLIED"
    assert out["durable"] is False and out["backend_halt"] == "UNVERIFIED"
    r = rig.client.reconcile_stop(rig.stop(2))
    if mode in ("drop_before", "drop_after"):
        assert r["verdict"] == "UNKNOWN" and r["stop_recorded"] is False
    if mode == "garbage":
        assert r["stop_recorded"] is False


# ---- idempotent retry

def test_identical_retry_is_already_applied_and_changes_nothing(rig):
    rig.arm_to(1)
    env = rig.stop(2)
    assert rig.client.submit_stop(env)["outcome"] == "STOP_RECORDED"
    head = rig.gate._latch.head
    pushes = len(rig.pushes)
    for _ in range(3):
        out = rig.client.submit_stop(env)
        assert out["outcome"] == "ALREADY_APPLIED" and out["durable"] is True
        assert rig.gate._latch.head == head
    assert len(rig.pushes) == pushes + 3  # notice re-sent each retry
    assert rig.pushes[-1]["allowed"] is False and rig.pushes[-1]["sequence"] == 2


def test_already_applied_cannot_bypass_signature(rig):
    rig.arm_to(1)
    env = rig.stop(2)
    assert rig.client.submit_stop(env)["outcome"] == "STOP_RECORDED"
    forged = dict(env, signature=("0" if env["signature"][0] != "0" else "1") + env["signature"][1:])
    r = rig.gate.handle({"type": "command", "envelope": forged})
    assert (r["ok"], r["reason"]) == (False, "authentication_failed")
    attacker = Ed25519PrivateKey.generate()
    r = rig.gate.handle({"type": "command", "envelope": signed(attacker, "stop-k1", 2, "stop")})
    assert (r["ok"], r["reason"]) == (False, "authentication_failed")
    r = rig.gate.handle({"type": "command", "envelope": dict(env, latch_id="other-latch")})
    assert r["ok"] is False and r["reason"] in ("wrong_latch", "authentication_failed")


def test_already_applied_requires_matching_durable_record(rig):
    rig.arm_to(1)
    env = rig.stop(2)
    assert rig.client.submit_stop(env)["outcome"] == "STOP_RECORDED"
    os.unlink(os.path.join(rig.state, "store.json"))
    r = rig.gate.handle({"type": "command", "envelope": env})
    assert r["ok"] is False and r["reason"] == "stale_or_replayed"
    assert rig.client.reconcile_stop(env)["verdict"] == "UNVERIFIABLE"
    assert rig.client.reconcile_stop(env)["stop_recorded"] is False


def test_anchor_rollback_makes_reconcile_unverifiable(rig):
    rig.arm_to(1)
    env = rig.stop(2)
    assert rig.client.submit_stop(env)["outcome"] == "STOP_RECORDED"
    with open(os.path.join(rig.state, "anchor.json"), "w") as fh:
        json.dump({"sequence": 1, "digest": "00" * 32}, fh)
    r = rig.client.reconcile_stop(env)
    assert r["verdict"] == "UNVERIFIABLE" and r["stop_recorded"] is False
    assert rig.client.submit_stop(env)["outcome"] != "ALREADY_APPLIED"


def test_retry_after_gate_restart_is_still_already_applied(rig):
    rig.arm_to(1)
    env = rig.stop(2)
    assert rig.client.submit_stop(env)["outcome"] == "STOP_RECORDED"
    gate2 = eg.GateCore(
        rig.state, LATCH, {"stop-k1": pub(rig.stop1), "stop-k2": pub(rig.stop2)},
        {"arm-k1": pub(rig.arm)}, frozenset({"echo"}),
    )
    r = gate2.handle({"type": "command", "envelope": env})
    assert (r["ok"], r["reason"]) == (True, "already_applied")
    assert gate2.reconcile(env)["verdict"] == "EXACT_APPLIED"


# ---- conflicts, stale, newer, unrelated

def test_conflicting_stop_same_sequence_rejected_and_distinguished(rig):
    rig.arm_to(1)
    mine, other = rig.stop(2), rig.stop(2, "stop2", "stop-k2")
    assert rig.client.submit_stop(mine)["outcome"] == "STOP_RECORDED"
    out = rig.client.submit_stop(other)
    assert out["outcome"] == "REJECTED" and out["reason"] == "conflicting_command"
    assert out["durable"] is False
    assert rig.client.reconcile_stop(other)["verdict"] == "CONFLICT"
    assert rig.client.reconcile_stop(other)["stop_recorded"] is False
    assert rig.client.reconcile_stop(mine)["verdict"] == "EXACT_APPLIED"


def test_sequence_advancement_is_not_proof_of_a_specific_stop(rig):
    rig.arm_to(1)
    mine, theirs = rig.stop(2), rig.stop(3, "stop2", "stop-k2")
    rig.client.mode = "drop_before"
    assert rig.client.submit_stop(mine)["outcome"] == "UNKNOWN"
    rig.client.mode = "ok"
    assert rig.client.submit_stop(theirs)["outcome"] == "STOP_RECORDED"  # unrelated newer STOP
    r = rig.client.reconcile_stop(mine)
    assert r["verdict"] == "SUPERSEDED_UNVERIFIED" and r["stop_recorded"] is False
    assert r["head_sequence"] == 3
    # a late retry of the older command is stale, not already_applied
    out = rig.client.submit_stop(mine)
    assert out["outcome"] == "REJECTED" and out["reason"] == "stale_or_replayed"
    assert rig.client.reconcile_stop(theirs)["verdict"] == "EXACT_APPLIED"


def test_stale_stop_rejected(rig):
    rig.arm_to(1)
    assert rig.client.submit_stop(rig.stop(3))["outcome"] == "STOP_RECORDED"  # gap allowed for STOP
    out = rig.client.submit_stop(rig.stop(2))
    assert out["reason"] == "stale_or_replayed" and out["durable"] is False


def test_arm_behaviour_unchanged(rig):
    rig.arm_to(1)
    arm1 = signed(rig.arm, "arm-k1", 1, "arm")
    assert rig.gate.handle({"type": "command", "envelope": arm1})["reason"] == "stale_or_replayed"
    out = rig.client.submit_stop(arm1)
    assert out["outcome"] == "REJECTED" and out["reason"] == "not_a_stop_command"
    assert rig.client.delivered == 0
    assert rig.client.submit_stop(rig.stop(2))["outcome"] == "STOP_RECORDED"
    arm2 = signed(rig.arm, "arm-k1", 3, "arm")
    assert rig.gate.handle({"type": "command", "envelope": arm2})["ok"] is True  # ARM path untouched
    assert rig.gate.handle({"type": "command", "envelope": arm2})["reason"] == "stale_or_replayed"


# ---- backend acknowledgement is not halt evidence

@pytest.mark.parametrize("ack", [True, False])
def test_backend_ack_never_claims_halt(rig, ack):
    rig.arm_to(1)
    rig.ack = ack
    out = rig.client.submit_stop(rig.stop(2))
    assert out["outcome"] == "STOP_RECORDED" and out["durable"] is True
    assert out["backend_notice"] == ("acknowledged" if ack else "unconfirmed")
    assert out["backend_halt"] == "UNVERIFIED"


def test_uncertain_backend_ack_retry_resends_notice(rig):
    rig.arm_to(1)
    rig.deliver_notices = False  # notice lost on the way to the backend
    rig.ack = False
    env = rig.stop(2)
    assert rig.client.submit_stop(env)["backend_notice"] == "unconfirmed"
    assert rig.backend._allowed is True
    rig.deliver_notices, rig.ack = True, True
    out = rig.client.submit_stop(env)
    assert out["outcome"] == "ALREADY_APPLIED" and out["backend_notice"] == "acknowledged"
    assert rig.backend._allowed is False


# ---- residual execution window (documented, not changed)

def test_residual_window_between_stop_and_backend_notice(rig):
    rig.arm_to(1)
    d1, d2 = eg.args_digest({"x": 1}), eg.args_digest({"x": 2})
    p1 = rig.gate.authorize("echo", d1)["token"]
    p2 = rig.gate.authorize("echo", d2)["token"]
    rig.deliver_notices, rig.ack = False, False
    assert rig.client.submit_stop(rig.stop(2))["durable"] is True
    assert not rig.gate.authorize("echo", "0" * 64)["ok"]  # gate issues nothing new
    # The already-issued permit is still honoured: the backend has not heard.
    assert rig.backend.execute("echo", {"x": 1}, p1)["ok"] is True
    # The window ends at notice staleness (3.0 s), not at the 5 s token TTL.
    rig.mono[0] += 3.01
    assert rig.backend.execute("echo", {"x": 2}, p2)["reason"] == "gate_notice_stale"


def test_issued_permit_refused_immediately_once_notice_arrives(rig):
    rig.arm_to(1)
    p = rig.gate.authorize("echo", eg.args_digest({"x": 1}))["token"]
    assert rig.client.submit_stop(rig.stop(2))["durable"] is True
    assert rig.backend.execute("echo", {"x": 1}, p)["reason"] == "gate_not_armed"


# ---- concurrency

def test_concurrent_identical_stop_retries_are_idempotent(rig):
    rig.arm_to(1)
    env = rig.stop(2)
    results, barrier = [], threading.Barrier(8)

    def worker():
        barrier.wait()
        results.append(rig.gate.handle({"type": "command", "envelope": env})["reason"])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(results) == ["accepted"] + ["already_applied"] * 7
    assert rig.gate._latch.head.sequence == 2
    assert rig.client.reconcile_stop(env)["verdict"] == "EXACT_APPLIED"


def test_concurrent_conflicting_stops_only_one_wins(rig):
    rig.arm_to(1)
    a, b = rig.stop(2), rig.stop(2, "stop2", "stop-k2")
    results, barrier = {}, threading.Barrier(2)

    def worker(name, env):
        barrier.wait()
        results[name] = rig.gate.handle({"type": "command", "envelope": env})["reason"]

    ts = [threading.Thread(target=worker, args=("a", a)), threading.Thread(target=worker, args=("b", b))]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(results.values()) == ["accepted", "conflicting_command"]
    verdicts = {rig.client.reconcile_stop(e)["verdict"] for e in (a, b)}
    assert verdicts == {"EXACT_APPLIED", "CONFLICT"}


# ---- review fixes (adversarial regressions)

def _files(rig):
    return [os.path.join(rig.state, n) for n in ("anchor.json", "store.json")]


def test_coherent_rollback_to_older_stop_while_live_latch_is_armed_is_not_exact(rig):
    rig.arm_to(1)
    old = rig.stop(2)
    assert rig.client.submit_stop(old)["outcome"] == "STOP_RECORDED"
    saved = [open(f).read() for f in _files(rig)]
    rig.gate._latch._status = sl.STATUS_ARMED  # live latch re-armed at a newer head
    rig.gate._latch._head = sl.AnchorHead(3, "ab" * 32)
    for f, data in zip(_files(rig), saved):
        open(f, "w").write(data)  # attacker restores the older, valid, coherent pair
    r = rig.client.reconcile_stop(old)
    assert r["verdict"] == "UNVERIFIABLE" and r["ok"] is False and r["stop_recorded"] is False


def test_coherent_rollback_below_live_head_is_unverifiable(rig):
    rig.arm_to(1)
    assert rig.client.submit_stop(rig.stop(2))["outcome"] == "STOP_RECORDED"
    older = [open(f).read() for f in _files(rig)]
    arm3 = signed(rig.arm, "arm-k1", 3, "arm")
    assert rig.gate.handle({"type": "command", "envelope": arm3})["ok"]
    stop4 = rig.stop(4)
    assert rig.client.submit_stop(stop4)["outcome"] == "STOP_RECORDED"
    for f, data in zip(_files(rig), older):
        open(f, "w").write(data)
    for env in (rig.stop(2), stop4):
        r = rig.client.reconcile_stop(env)
        assert r["verdict"] == "UNVERIFIABLE" and r["stop_recorded"] is False


def test_store_substituted_with_other_valid_stop_is_unverifiable(rig):
    rig.arm_to(1)
    mine = rig.stop(2)
    assert rig.client.submit_stop(mine)["outcome"] == "STOP_RECORDED"
    other = rig.stop(2, "stop2", "stop-k2")
    with open(os.path.join(rig.state, "store.json"), "w") as fh:
        json.dump(other, fh)
    for env in (mine, other):
        r = rig.client.reconcile_stop(env)
        assert r["verdict"] == "UNVERIFIABLE" and r["stop_recorded"] is False
    assert rig.client.submit_stop(mine)["outcome"] != "ALREADY_APPLIED"


@pytest.mark.parametrize("seq, expect_ok, verdict", [
    (3, False, "NOT_APPLIED"), (2, True, "EXACT_APPLIED"), (1, False, "SUPERSEDED_UNVERIFIED"),
])
def test_ok_is_true_only_for_exact_applied(rig, seq, expect_ok, verdict):
    rig.arm_to(1)
    assert rig.client.submit_stop(rig.stop(2))["outcome"] == "STOP_RECORDED"
    r = rig.client.reconcile_stop(rig.stop(seq))
    assert (r["ok"], r["verdict"], r["stop_recorded"]) == (expect_ok, verdict, expect_ok)
    conflict = rig.client.reconcile_stop(rig.stop(2, "stop2", "stop-k2"))
    assert conflict["verdict"] == "CONFLICT" and conflict["ok"] is False


def test_unauthenticated_rejections_reveal_no_latch_state(rig):
    rig.arm_to(1)
    attacker = Ed25519PrivateKey.generate()
    for env in (signed(attacker, "stop-k1", 2, "stop"),
                signed(attacker, "stop-k1", 2, "stop", latch_id="other-latch")):
        r = rig.gate.reconcile(env)
        assert r["reason"] == "authentication_failed"
        assert r["status"] == "" and r["head_sequence"] is None


def test_reconcile_concurrent_with_apply_only_sees_consistent_verdicts(rig):
    rig.arm_to(1)
    env = rig.stop(2)
    seen, barrier = [], threading.Barrier(5)

    def reader():
        barrier.wait()
        for _ in range(50):
            seen.append(rig.gate.reconcile(env)["verdict"])

    def writer():
        barrier.wait()
        rig.gate.handle({"type": "command", "envelope": env})

    ts = [threading.Thread(target=reader) for _ in range(4)] + [threading.Thread(target=writer)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert set(seen) <= {"NOT_APPLIED", "EXACT_APPLIED"}
    assert rig.gate.reconcile(env)["verdict"] == "EXACT_APPLIED"
