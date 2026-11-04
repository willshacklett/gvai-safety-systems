import copy
import threading

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from gvai import experimental_stop_latch as sl
from gvai.experimental_stop_latch import (
    AnchorHead,
    InMemoryCommandStore,
    InMemoryTrustedAnchor,
    StopLatch,
    StopLatchConfigError,
    StopLatchKeyring,
)

LATCH = "latch-1"


def pub(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


class Env:
    def __init__(self):
        self.stop_key = Ed25519PrivateKey.generate()
        self.arm_key = Ed25519PrivateKey.generate()
        self.other_key = Ed25519PrivateKey.generate()
        self.keyring = StopLatchKeyring(
            {"stop-k1": pub(self.stop_key)}, {"arm-k1": pub(self.arm_key)}
        )
        self.anchor = InMemoryTrustedAnchor()
        self.store = InMemoryCommandStore()

    def latch(self):
        return StopLatch(LATCH, self.keyring, self.anchor, self.store)

    def cmd(self, seq, kind, key=None, key_id=None, latch_id=LATCH):
        key = key or (self.stop_key if kind == "stop" else self.arm_key)
        key_id = key_id or ("stop-k1" if kind == "stop" else "arm-k1")
        sig = key.sign(sl.signing_bytes(latch_id, seq, kind, key_id))
        return {
            "version": 1,
            "latch_id": latch_id,
            "sequence": seq,
            "command_type": kind,
            "key_id": key_id,
            "signature": sig.hex(),
        }


@pytest.fixture
def env():
    return Env()


@pytest.fixture
def armed(env):
    latch = env.latch()
    assert env.latch().permit().allowed is False
    assert latch.apply(env.cmd(1, "arm")).accepted
    assert latch.permit().allowed
    return env, latch


def test_documented_enforcement_model_is_not_independent():
    assert sl.INDEPENDENT_ENFORCEMENT_IMPLEMENTED is False
    assert sl.ENFORCEMENT_MODEL == "in_process_verification_only"


def test_fresh_latch_is_fail_closed(env):
    d = env.latch().permit()
    assert (d.allowed, d.status) == (False, "stopped")


def test_arm_then_stop(armed):
    env, latch = armed
    r = latch.apply(env.cmd(2, "stop"))
    assert r.accepted and not r.gap_detected
    assert latch.permit().allowed is False
    assert latch.status == "stopped"


def test_stop_cannot_be_reopened_by_replayed_arm(armed):
    env, latch = armed
    old_arm = env.cmd(1, "arm")
    latch.apply(env.cmd(2, "stop"))
    assert latch.apply(old_arm).reason == "stale_or_replayed"
    assert not latch.permit().allowed


def test_replayed_stop_rejected_without_state_change(armed):
    env, latch = armed
    stop = env.cmd(2, "stop")
    assert latch.apply(stop).accepted
    # Reconciliation V1: an identical retry is recognised, never newly accepted.
    replay = latch.apply(stop)
    assert not replay.accepted and replay.reason == "already_applied"
    assert env.anchor.read().sequence == 2
    assert latch.apply(env.cmd(1, "stop")).reason == "stale_or_replayed"


def test_rearm_requires_contiguous_sequence(armed):
    env, latch = armed
    latch.apply(env.cmd(2, "stop"))
    assert latch.apply(env.cmd(4, "arm")).reason == "sequence_gap"
    assert not latch.permit().allowed
    assert latch.apply(env.cmd(3, "arm")).accepted
    assert latch.permit().allowed


def test_authentic_stop_across_gap_is_honoured_and_flagged(armed):
    env, latch = armed
    r = latch.apply(env.cmd(9, "stop"))
    assert r.accepted and r.gap_detected and latch.gap_detected
    assert not latch.permit().allowed
    assert latch.apply(env.cmd(10, "arm")).accepted


def test_forged_signature_does_not_stop_or_arm(armed):
    env, latch = armed
    forged = env.cmd(2, "stop", key=env.other_key)
    assert latch.apply(forged).reason == "authentication_failed"
    assert latch.permit().allowed
    fresh = Env().latch()
    assert fresh.apply(Env().cmd(1, "arm")).reason == "authentication_failed"
    assert not fresh.permit().allowed


def test_key_separation_roles(armed):
    env, latch = armed
    # arm key cannot stop; stop key cannot arm
    assert latch.apply(env.cmd(2, "stop", key=env.arm_key, key_id="arm-k1")).reason == (
        "authentication_failed"
    )
    latch.apply(env.cmd(2, "stop"))
    assert latch.apply(env.cmd(3, "arm", key=env.stop_key, key_id="stop-k1")).reason == (
        "authentication_failed"
    )
    assert not latch.permit().allowed


def test_keyring_rejects_shared_or_forbidden_keys():
    a, b = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    with pytest.raises(StopLatchConfigError):
        StopLatchKeyring({"k1": pub(a)}, {"k1": pub(b)})
    with pytest.raises(StopLatchConfigError):
        StopLatchKeyring({"k1": pub(a)}, {"k2": pub(a)})
    with pytest.raises(StopLatchConfigError):
        StopLatchKeyring({"k1": pub(a)}, {"k2": pub(b)}, [pub(b)])
    with pytest.raises(StopLatchConfigError):
        StopLatchKeyring({}, {"k2": pub(b)})
    with pytest.raises(StopLatchConfigError):
        StopLatchKeyring({"k1": b"short"}, {"k2": pub(b)})
    with pytest.raises(StopLatchConfigError):
        StopLatchKeyring({"bad key": pub(a)}, {"k2": pub(b)})


def test_keyring_holds_no_private_material(env):
    assert not any(
        hasattr(env.keyring, n) for n in ("sign", "private_key", "_private")
    )


def test_domain_separation(armed):
    env, latch = armed
    payload = sl.signing_bytes(LATCH, 2, "stop", "stop-k1")
    raw = payload[len(sl._DOMAIN):]
    bad = env.cmd(2, "stop")
    bad["signature"] = env.stop_key.sign(raw).hex()
    assert latch.apply(bad).reason == "authentication_failed"


@pytest.mark.parametrize(
    "field,value",
    [
        ("latch_id", "other-latch"),
        ("sequence", 3),
        ("command_type", "arm"),
        ("key_id", "arm-k1"),
    ],
)
def test_tampered_fields_rejected(armed, field, value):
    env, latch = armed
    cmd = env.cmd(2, "stop")
    cmd[field] = value
    assert not latch.apply(cmd).accepted
    assert latch.permit().allowed


def test_wrong_latch_id_signed_correctly_still_rejected(armed):
    env, latch = armed
    r = latch.apply(env.cmd(2, "stop", latch_id="other-latch"))
    assert r.reason == "wrong_latch"
    assert latch.permit().allowed


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(extra=1),
        lambda c: c.pop("signature"),
        lambda c: c.update(version=2),
        lambda c: c.update(version=True),
        lambda c: c.update(sequence=True),
        lambda c: c.update(sequence=2.0),
        lambda c: c.update(sequence="2"),
        lambda c: c.update(sequence=0),
        lambda c: c.update(sequence=-1),
        lambda c: c.update(sequence=2**64),
        lambda c: c.update(command_type="shutdown"),
        lambda c: c.update(signature=c["signature"].upper()),
        lambda c: c.update(signature=c["signature"][:-2]),
        lambda c: c.update(signature=None),
        lambda c: c.update(latch_id="a b"),
        lambda c: c.update(key_id=""),
    ],
)
def test_malformed_envelopes_rejected(armed, mutate):
    env, latch = armed
    cmd = env.cmd(2, "stop")
    mutate(cmd)
    assert not latch.apply(cmd).accepted
    assert latch.permit().allowed


@pytest.mark.parametrize("bad", [None, [], "stop", 7, b"x"])
def test_non_mapping_envelopes_rejected(armed, bad):
    _, latch = armed
    assert not latch.apply(bad).accepted
    assert latch.permit().allowed


def test_anchor_rollback_detected_by_permit(armed):
    env, latch = armed
    latch.apply(env.cmd(2, "stop"))
    latch.apply(env.cmd(3, "arm"))
    env.anchor._head = AnchorHead(1, "0" * 64)  # attacker rewinds anchor
    d = latch.permit()
    assert (d.allowed, d.status, d.reason) == (False, "fault", "anchor_rollback_detected")


def test_anchor_rollback_blocks_apply_and_is_sticky(armed):
    env, latch = armed
    env.anchor._head = sl.GENESIS_HEAD
    r = latch.apply(env.cmd(2, "stop"))
    assert r.reason == "anchor_rollback_detected"
    assert latch.apply(env.cmd(2, "arm")).status == "fault"
    env.anchor._head = latch._head
    assert not latch.permit().allowed


def test_arm_cannot_clear_fault(armed):
    env, latch = armed
    env.anchor._head = sl.GENESIS_HEAD
    latch.permit()
    assert not latch.apply(env.cmd(2, "arm")).accepted
    assert not latch.permit().allowed


def test_store_rollback_detected_on_restart(armed):
    env, latch = armed
    old = copy.deepcopy(env.store.load())  # arm@1
    latch.apply(env.cmd(2, "stop"))
    latch.apply(env.cmd(3, "arm"))
    env.store.save(old)  # attacker restores the older armed state
    restarted = env.latch()
    d = restarted.permit()
    assert (d.allowed, d.reason) == (False, "store_rollback_detected")


def test_store_deleted_after_anchor_advanced_faults(armed):
    env, _ = armed
    env.store._envelope = None
    assert env.latch().permit().reason == "store_missing_but_anchor_advanced"


def test_store_forked_command_at_same_sequence_faults(armed):
    env, latch = armed
    latch.apply(env.cmd(2, "stop"))
    # authentic but different command at the anchor's sequence (arm@2 instead of stop@2)
    env.store.save(env.cmd(2, "arm"))
    assert env.latch().permit().reason == "store_anchor_mismatch"


def test_store_tampering_faults(armed):
    env, latch = armed
    latch.apply(env.cmd(2, "stop"))
    tampered = dict(env.store.load())
    tampered["command_type"] = "arm"
    env.store.save(tampered)
    assert env.latch().permit().reason == "store_signature_invalid"
    env.store.save({"junk": 1})
    assert env.latch().permit().reason == "store_corrupt"


def test_store_command_for_other_latch_faults(env):
    env.store.save(env.cmd(1, "arm", latch_id="other-latch"))
    assert env.latch().status == "fault"


def test_restart_preserves_stop_and_armed_state(armed):
    env, latch = armed
    assert env.latch().permit().allowed
    latch.apply(env.cmd(2, "stop"))
    restarted = env.latch()
    assert restarted.status == "stopped" and not restarted.permit().allowed


def test_anchor_ahead_of_local_state_faults(armed):
    env, latch = armed
    env.anchor.compare_and_advance(env.anchor.read(), AnchorHead(2, "a" * 64))
    d = latch.permit()
    assert (d.allowed, d.reason) == (False, "anchor_diverged")


class RaisingAnchor(InMemoryTrustedAnchor):
    fail_read = False
    fail_cas = False

    def read(self):
        if self.fail_read:
            raise RuntimeError("down")
        return super().read()

    def compare_and_advance(self, expected, new):
        if self.fail_cas:
            raise RuntimeError("down")
        return super().compare_and_advance(expected, new)


def test_anchor_unavailable_denies_and_recovers_without_fault():
    e = Env()
    e.anchor = RaisingAnchor()
    latch = e.latch()
    latch.apply(e.cmd(1, "arm"))
    e.anchor.fail_read = True
    d = latch.permit()
    assert (d.allowed, d.reason) == (False, "anchor_unavailable")
    assert latch.apply(e.cmd(2, "stop")).reason == "anchor_unavailable"
    e.anchor.fail_read = False
    assert latch.permit().allowed


def test_anchor_unavailable_at_startup_faults():
    e = Env()
    e.anchor = RaisingAnchor()
    e.anchor.fail_read = True
    assert e.latch().status == "fault"


def test_anchor_returning_garbage_denies(armed):
    env, latch = armed
    env.anchor.read = lambda: ("x", 1)
    assert not latch.permit().allowed


def test_stop_taken_even_if_anchor_cannot_record_it():
    e = Env()
    e.anchor = RaisingAnchor()
    latch = e.latch()
    latch.apply(e.cmd(1, "arm"))
    e.anchor.fail_cas = True
    r = latch.apply(e.cmd(2, "stop"))
    assert not r.accepted and r.reason == "anchor_advance_failed"
    assert not latch.permit().allowed and latch.status == "fault"


def test_arm_not_granted_if_anchor_cannot_record_it():
    e = Env()
    e.anchor = RaisingAnchor()
    e.anchor.fail_cas = True
    latch = e.latch()
    assert latch.apply(e.cmd(1, "arm")).reason == "anchor_advance_failed"
    assert not latch.permit().allowed


def test_store_write_failure_fails_closed(env):
    class Bad(InMemoryCommandStore):
        def save(self, envelope):
            raise OSError("disk")

    env.store = Bad()
    latch = env.latch()
    r = latch.apply(env.cmd(1, "arm"))
    assert not r.accepted and r.reason == "store_write_failed"
    assert not latch.permit().allowed


def test_anchor_rejects_non_monotonic_advance():
    a = InMemoryTrustedAnchor()
    assert a.compare_and_advance(sl.GENESIS_HEAD, AnchorHead(2, "a" * 64))
    assert not a.compare_and_advance(AnchorHead(2, "a" * 64), AnchorHead(2, "b" * 64))
    assert not a.compare_and_advance(AnchorHead(2, "a" * 64), AnchorHead(1, "b" * 64))
    assert not a.compare_and_advance(sl.GENESIS_HEAD, AnchorHead(3, "c" * 64))


def test_concurrent_same_sequence_has_exactly_one_winner(env):
    latch = env.latch()
    latch.apply(env.cmd(1, "arm"))
    cmds = [env.cmd(2, "stop"), env.cmd(2, "stop")]
    results = []
    threads = [
        threading.Thread(target=lambda c=c: results.append(latch.apply(c)))
        for c in cmds * 8
    ]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(r.accepted for r in results) == 1
    assert env.anchor.read().sequence == 2


def test_permit_never_raises_on_internal_failure(armed):
    env, latch = armed
    env.anchor.read = lambda: 1 / 0
    assert latch.permit().allowed is False


def test_stop_latch_does_not_expose_signing(env):
    assert not hasattr(sl, "sign_command")
    assert not hasattr(sl.StopLatch, "sign")
