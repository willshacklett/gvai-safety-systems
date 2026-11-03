"""Reconstructed ARM expiration contracts, not a recovered commit or V2 implementation.

V1 observations pass. Proposed requirements use strict, narrowly scoped xfails.
Time contracts deliberately exercise accepted V1 ARM commands with a declared
test-side deadline: V1 has no place to carry that deadline. Separate wire tests
exercise signed V2 envelopes without stripping fields or translating signatures.
All persistence, clock faults and commit stalls are in memory.
"""

import copy
import json
import threading
from contextlib import contextmanager
from dataclasses import dataclass

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import experimental_external_gate as eg
from gvai import experimental_stop_latch as sl

LATCH = "arm-expiry-prototype"
V2_DOMAIN = b"GVAI-ARM-AUTHORIZATION-V2\n"
WATCHDOG = 5


class MissingRequirement(AssertionError):
    """Only an explicit proposed-contract violation may be expected to fail."""


def require(condition, message):
    if not condition:
        raise MissingRequirement(message)


proposed = pytest.mark.xfail(
    strict=True,
    raises=MissingRequirement,
    reason="Proposed ARM V2 requirement; not implemented at fb225cb",
)


def public_bytes(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


class Clock:
    def __init__(self):
        self.now = 100
        self.failure = None

    def __call__(self):
        if self.failure is not None:
            raise self.failure
        return self.now


@dataclass(frozen=True)
class Window:
    """Proposed signed time window, not fed to or enforced by the V1 latch."""

    not_before: int = 100
    not_after: int = 110


class Crash(BaseException):
    """Model process loss, bypassing the production Exception handlers."""


class Store(sl.InMemoryCommandStore):
    def __init__(self):
        super().__init__()
        self.pause_sequence = None
        self.entered = threading.Event()
        self.release = threading.Event()
        self.crash = False
        self.on_save = None

    def save(self, envelope):
        if envelope["sequence"] == self.pause_sequence:
            self.entered.set()
            assert self.release.wait(WATCHDOG), "commit release watchdog expired"
        if self.on_save is not None:
            self.on_save()
        if self.crash:
            raise Crash("after anchor advancement, before persistence")
        super().save(envelope)


class Keyring(sl.StopLatchKeyring):
    def __init__(self, stop_key, arm_key):
        super().__init__(
            {"stop-k1": public_bytes(stop_key)}, {"arm-k1": public_bytes(arm_key)}
        )
        self.observed = None
        self.verified = threading.Event()

    def verify(self, command):
        valid = super().verify(command)
        if valid and (command.sequence, command.command_type) == self.observed:
            self.verified.set()
        return valid


class Rig:
    def __init__(self):
        self.stop_key = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32)
        self.arm_key = Ed25519PrivateKey.from_private_bytes(b"\x02" * 32)
        self.anchor = sl.InMemoryTrustedAnchor()
        self.store = Store()
        self.keyring = Keyring(self.stop_key, self.arm_key)
        self.clock = Clock()
        self.window = Window()
        self.latch = self.restart()

    def restart(self):
        return sl.StopLatch(LATCH, self.keyring, self.anchor, self.store)

    def command(self, sequence, kind):
        key_id = "arm-k1" if kind == "arm" else "stop-k1"
        key = self.arm_key if kind == "arm" else self.stop_key
        return {
            "version": 1,
            "latch_id": LATCH,
            "sequence": sequence,
            "command_type": kind,
            "key_id": key_id,
            "signature": key.sign(
                sl.signing_bytes(LATCH, sequence, kind, key_id)
            ).hex(),
        }

    def arm(self, sequence=1):
        result = self.latch.apply(self.command(sequence, "arm"))
        assert result.accepted, result
        return result

    def stop(self, sequence):
        result = self.latch.apply(self.command(sequence, "stop"))
        assert result.accepted, result
        return result


@pytest.fixture
def rig():
    return Rig()


@pytest.fixture
def gate(rig, monkeypatch):
    """Use the real GateCore constructor/logic, replacing all file state."""
    monkeypatch.setattr(eg, "FileTrustedAnchor", lambda path: rig.anchor)
    monkeypatch.setattr(eg, "FileCommandStore", lambda path: rig.store)
    monkeypatch.setattr(eg, "_load_or_create_gate_seed", lambda path: b"\x03" * 32)
    # The existing worktree directory is not created or used for persistence.
    core = eg.GateCore(
        "/workspaces/gvai-arm-expiry-v1",
        LATCH,
        {"stop-k1": public_bytes(rig.stop_key)},
        {"arm-k1": public_bytes(rig.arm_key)},
        frozenset({"echo"}),
        clock=rig.clock,
    )
    rig.latch = core._latch
    return core


@contextmanager
def running(call):
    """Watchdogs detect deadlock; events, not elapsed time, select the order."""
    results, errors = [], []

    def worker():
        try:
            results.append(call())
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        yield results
    finally:
        thread.join(WATCHDOG)
        assert not thread.is_alive(), "worker did not finish"
        if errors:
            raise errors[0]


@contextmanager
def stalled(rig, command):
    rig.store.pause_sequence = command["sequence"]
    with running(lambda: rig.latch.apply(command)) as results:
        try:
            assert rig.store.entered.wait(WATCHDOG), "store was not reached"
            yield results
        finally:
            rig.store.release.set()


def ordered_race(rig, first, second):
    rig.keyring.observed = (second["sequence"], second["command_type"])
    with running(lambda: submit_after_stall(rig, second)) as second_results:
        with stalled(rig, first) as first_results:
            assert rig.keyring.verified.wait(WATCHDOG), "second command not verified"
            assert second_results == []
    assert len(first_results) == len(second_results) == 1
    return first_results[0], second_results[0]


def submit_after_stall(rig, command):
    assert rig.store.entered.wait(WATCHDOG), "first command never reached commit"
    return rig.latch.apply(command)


def test_current_arm_n_plus_1_stalled_stop_n_plus_2_waits_ends_stopped(rig):
    rig.arm(1)
    first, second = ordered_race(
        rig, rig.command(2, "arm"), rig.command(3, "stop")
    )
    assert first.accepted and second.accepted
    assert rig.anchor.read().sequence == 3
    assert rig.store.load()["command_type"] == "stop"
    assert (rig.latch.permit().allowed, rig.latch.status) == (False, "stopped")


@pytest.mark.parametrize("first_kind", ["arm", "stop"])
def test_current_same_sequence_race_first_committer_wins(rig, first_kind):
    second_kind = "stop" if first_kind == "arm" else "arm"
    first, second = ordered_race(
        rig, rig.command(1, first_kind), rig.command(1, second_kind)
    )
    assert first.accepted and not second.accepted
    assert second.reason == (
        "conflicting_command" if second_kind == "stop" else "stale_or_replayed"
    )
    assert rig.anchor.read().sequence == 1
    assert rig.latch.permit().allowed == (first_kind == "arm")


@proposed
def test_proposed_stop_wins_same_sequence_even_when_arm_commits_first(rig):
    first, second = ordered_race(
        rig, rig.command(1, "arm"), rig.command(1, "stop")
    )
    assert first.accepted
    require(
        second.accepted and not rig.latch.permit().allowed,
        "V1 rejects the same-sequence STOP after ARM and stays armed",
    )


def test_current_client_timeout_does_not_cancel_delayed_arm(rig):
    with stalled(rig, rig.command(1, "arm")) as results:
        # The client abandons its wait at this event; no transport/sleep needed.
        client_reply = {"ok": False, "reason": "communication_failure"}
        assert not client_reply["ok"] and results == []
        assert rig.anchor.read().sequence == 1
        assert rig.store.load() is None
    assert results[0].accepted
    assert rig.latch.permit().allowed
    assert rig.latch.reconcile(rig.command(1, "arm")).reason == "not_a_stop_command"


def test_current_replay_after_stop_rejected_but_unused_old_arm_is_fresh_by_sequence(rig):
    replay = rig.command(1, "arm")
    unused_old_arm = rig.command(3, "arm")
    rig.arm()
    rig.stop(2)
    rig.clock.now = 1_000_000
    assert rig.latch.apply(replay).reason == "stale_or_replayed"
    assert not rig.latch.permit().allowed
    assert rig.latch.apply(unused_old_arm).accepted
    assert rig.latch.permit().allowed


@proposed
def test_proposed_stop_invalidates_pre_stop_unused_arm_authorization(rig):
    old_arm = rig.command(3, "arm")
    rig.arm()
    rig.stop(2)
    result = rig.latch.apply(old_arm)
    require(
        not result.accepted and not rig.latch.permit().allowed,
        "Sequence continuity does not bind ARM to the latest STOP generation",
    )


@pytest.mark.parametrize("previous", ["genesis", "arm", "stop"])
def test_current_crash_between_anchor_and_store_is_fail_closed(rig, previous):
    if previous != "genesis":
        rig.arm()
    if previous == "stop":
        rig.stop(2)
    saved = copy.deepcopy(rig.store.load())
    next_sequence = rig.anchor.read().sequence + 1
    rig.store.crash = True
    with pytest.raises(Crash):
        rig.latch.apply(rig.command(next_sequence, "arm"))
    assert rig.anchor.read().sequence == next_sequence
    assert rig.store.load() == saved
    # The crashed process must not be consulted; construct a new verifier.
    restarted = rig.restart()
    decision = restarted.permit()
    assert (decision.allowed, decision.status) == (False, "fault")
    assert decision.reason == (
        "store_missing_but_anchor_advanced"
        if previous == "genesis" else "store_rollback_detected"
    )
    assert not restarted.apply(rig.command(next_sequence + 1, "arm")).accepted


def test_current_arm_has_no_expiration_before_admission_or_at_permit(rig, gate):
    rig.clock.now = rig.window.not_after
    rig.arm()
    assert gate.authorize("echo", "0" * 64)["ok"]
    rig.clock.now += 1_000_000
    assert rig.restart().permit().allowed
    assert gate.authorize("echo", "0" * 64)["ok"]


@proposed
def test_proposed_expiration_before_admission(rig):
    rig.clock.now = rig.window.not_after
    result = rig.latch.apply(rig.command(1, "arm"))
    require(
        not result.accepted and rig.anchor.read() == sl.GENESIS_HEAD,
        "Expired ARM advanced the anchor at admission (V1 has no deadline input)",
    )


@proposed
def test_proposed_expiration_while_waiting_for_latch_lock(rig):
    arm = rig.command(2, "arm")
    rig.keyring.observed = (2, "arm")
    with running(lambda: submit_after_stall(rig, arm)) as arm_results:
        with stalled(rig, rig.command(1, "stop")) as stop_results:
            assert rig.keyring.verified.wait(WATCHDOG)
            assert arm_results == []
            rig.clock.now = rig.window.not_after
    assert stop_results[0].accepted
    require(
        not arm_results[0].accepted and not rig.latch.permit().allowed,
        "ARM authenticated before waiting commits after its declared deadline",
    )


@proposed
def test_proposed_expiration_during_commit_after_client_timeout(rig):
    with stalled(rig, rig.command(1, "arm")) as results:
        assert results == []
        rig.clock.now = rig.window.not_after
    require(
        not results[0].accepted and not rig.latch.permit().allowed,
        "Delayed ARM persistence completes after expiry and grants permission",
    )


@proposed
def test_proposed_expiration_between_anchor_advance_and_persistence(rig):
    def expire():
        assert rig.anchor.read().sequence == 1
        rig.clock.now = rig.window.not_after

    rig.store.on_save = expire
    result = rig.latch.apply(rig.command(1, "arm"))
    require(
        not result.accepted and not rig.latch.permit().allowed
        and not rig.restart().permit().allowed,
        "ARM becomes usable after crossing its deadline inside commit",
    )


@proposed
def test_proposed_fresh_authorization_at_permit_time(rig, gate):
    rig.arm()
    assert gate.authorize("echo", "0" * 64)["ok"]
    rig.clock.now = rig.window.not_after
    require(
        not gate.authorize("echo", "0" * 64)["ok"],
        "Gate issues a fresh token from an expired ARM authorization",
    )


def test_current_clock_failure_escapes_gate_and_latch_stays_armed(rig, gate):
    rig.arm()
    rig.clock.failure = RuntimeError("trusted clock unavailable")
    with pytest.raises(RuntimeError, match="trusted clock unavailable"):
        gate.authorize("echo", "0" * 64)
    assert rig.latch.permit().allowed


def test_current_clock_rollback_still_issues_permits(rig, gate):
    rig.arm()
    assert gate.authorize("echo", "0" * 64)["ok"]
    rig.clock.now = 99
    assert gate.authorize("echo", "0" * 64)["ok"]


def proposed_clock_denial(gate):
    try:
        reply = gate.authorize("echo", "0" * 64)
    except (RuntimeError, TypeError, ValueError) as exc:
        raise MissingRequirement("Clock fault escaped instead of structured denial") from exc
    require(not reply["ok"], "Clock fault permitted token issuance")


@proposed
def test_proposed_clock_failure_returns_fail_closed_decision(rig, gate):
    rig.arm()
    rig.clock.failure = RuntimeError("trusted clock unavailable")
    proposed_clock_denial(gate)


@proposed
def test_proposed_clock_rollback_is_sticky(rig, gate):
    rig.arm()
    assert gate.authorize("echo", "0" * 64)["ok"]
    rig.clock.now = 99
    proposed_clock_denial(gate)
    rig.clock.now = 105
    require(not gate.authorize("echo", "0" * 64)["ok"], "Rollback fault was cleared")


@pytest.mark.parametrize(
    "value",
    [None, True, "100", -1, 2**53 + 1, 100.5, float("nan"), float("inf"), float("-inf")],
    ids=["none", "bool", "string", "negative", "overflow", "fraction", "nan", "inf", "-inf"],
)
@proposed
def test_proposed_invalid_clock_values_fail_closed(rig, gate, value):
    rig.arm()
    rig.clock.now = value
    proposed_clock_denial(gate)


@pytest.mark.parametrize("now", [99, 100, 109, 110, 111])
def test_current_arm_admission_ignores_time_boundaries(rig, now):
    rig.clock.now = now
    rig.arm()
    assert rig.latch.permit().allowed


@pytest.mark.parametrize("now", [99, 110, 111], ids=["before", "at-expiry", "after"])
@proposed
def test_proposed_outside_half_open_window_denies(rig, now):
    rig.clock.now = now
    result = rig.latch.apply(rig.command(1, "arm"))
    require(not result.accepted, "ARM outside [not_before, not_after) was accepted")


def v2_signing_bytes(envelope):
    body = {key: value for key, value in envelope.items() if key != "signature"}
    return V2_DOMAIN + json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def v2_arm(rig, **changes):
    """Proposed wire format only; never converted to an accepted V1 command."""
    envelope = {
        "version": 2,
        "latch_id": LATCH,
        "sequence": 1,
        "command_type": "arm",
        "key_id": "arm-k1",
        "authority_id": "offline-arm-authority",
        "trust_domain": "independent-supervisor",
        "authorization_id": "authorization-1",
        "stop_generation": 0,
        "not_before": rig.window.not_before,
        "not_after": rig.window.not_after,
    }
    envelope.update(changes)
    envelope["signature"] = rig.arm_key.sign(v2_signing_bytes(envelope)).hex()
    return envelope


def test_current_v2_wire_is_rejected_not_silently_downgraded(rig):
    result = rig.latch.apply(v2_arm(rig))
    assert (result.accepted, result.reason) == (False, "malformed_envelope")
    assert rig.anchor.read() == sl.GENESIS_HEAD


@pytest.mark.parametrize("now", [100, 109], ids=["at-not-before", "last-valid-tick"])
@proposed
def test_proposed_valid_signed_v2_is_admitted_at_valid_boundaries(rig, now):
    rig.clock.now = now
    result = rig.latch.apply(v2_arm(rig))
    require(
        result.accepted and rig.latch.permit().allowed,
        "Production parser does not support valid signed ARM V2",
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("not_after", 111),
        ("not_before", 99),
        ("stop_generation", 1),
        ("authority_id", "service-owned-authority"),
        ("trust_domain", "commercial-service"),
        ("authorization_id", "authorization-2"),
        ("sequence", 2),
        ("latch_id", "other-latch"),
    ],
)
def test_proposed_signature_bytes_bind_expiration_and_authorization(rig, field, value):
    envelope = v2_arm(rig)
    signature = bytes.fromhex(envelope["signature"])
    rig.arm_key.public_key().verify(signature, v2_signing_bytes(envelope))
    tampered = dict(envelope, **{field: value})
    with pytest.raises(InvalidSignature):
        rig.arm_key.public_key().verify(signature, v2_signing_bytes(tampered))
    # V1 rejects the entire V2 schema, not specifically the tampered signature.
    assert rig.latch.apply(tampered).reason == "malformed_envelope"
    assert not rig.latch.permit().allowed


def test_proposed_v2_domain_is_not_v1_arm_signature(rig):
    envelope = v2_arm(rig)
    with pytest.raises(InvalidSignature):
        rig.arm_key.public_key().verify(
            bytes.fromhex(envelope["signature"]),
            sl.signing_bytes(LATCH, 1, "arm", "arm-k1"),
        )


def test_current_legacy_arm_is_accepted(rig):
    rig.arm()
    assert rig.latch.permit().allowed


@proposed
def test_proposed_v2_enforcement_rejects_legacy_arm(rig):
    # This is a desired enforcement contract, not a claim that a V2 mode exists.
    result = rig.latch.apply(rig.command(1, "arm"))
    require(
        not result.accepted and not rig.latch.permit().allowed,
        "V2 enforcement mode/legacy ARM rejection is absent",
    )
