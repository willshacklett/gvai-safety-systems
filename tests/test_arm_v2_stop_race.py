"""Test-only authority serialization, not an enforcer or durable authority."""

import threading
from contextlib import contextmanager
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import arm_v2_freshness as fresh
from gvai import experimental_stop_latch as sl

WATCHDOG = 5


def valid_generation(value):
    return type(value) is int and 0 <= value <= sl.ARM_V2_MAX_INTEGER


class Clock:
    def __init__(self):
        self.now = 100
        self.failure = False
        self.calls = 0

    def read(self):
        self.calls += 1
        if self.failure:
            raise RuntimeError("clock unavailable")
        return self.now


class State:
    """Volatile test reference: only the simulated supervisor may mutate it."""

    def __init__(self, generation=0):
        self.lock = threading.RLock()
        self.generation = generation
        self.high_generation = generation
        self.fault = None
        self.revoked = set()
        self.clock_mark = fresh.VolatileClockHighWater(0)
        self.unavailable = False


class Authority:
    """All checks, revocation and STOP use the same authority-owned lock.

    Nothing executes a workload. No method accepts cached decisions as input.
    Pauses are test hooks inside the critical section, not production callbacks.
    """

    def __init__(self, keyring, clock, state=None):
        self.keyring = keyring
        self.clock = clock
        self.state = state if state is not None else State()
        self.pause_kind = None
        self.entered = threading.Event()
        self.release = threading.Event()
        self.contender_kind = None
        self.contending = threading.Event()
        self.validator = fresh.ArmV2FreshnessValidator(
            clock=clock, generations=self, high_water=self.state.clock_mark,
        )

    @contextmanager
    def boundary(self, kind):
        if kind == self.contender_kind:
            self.contending.set()
        with self.state.lock:
            if kind == self.pause_kind:
                self.entered.set()
                assert self.release.wait(WATCHDOG), "boundary release watchdog expired"
            yield

    def state_reason(self):
        if self.state.unavailable:
            return "authority_unavailable"
        if self.state.fault:
            return self.state.fault
        if not (
            valid_generation(self.state.generation)
            and valid_generation(self.state.high_generation)
        ):
            self.state.fault = "authority_state_invalid"
        elif self.state.generation < self.state.high_generation:
            self.state.fault = "generation_rollback"
        elif self.state.generation != self.state.high_generation:
            self.state.fault = "authority_state_inconsistent"
        return self.state.fault

    def read(self):
        # B1 calls this inside the enclosing authority critical section.
        with self.state.lock:
            reason = self.state_reason()
            if reason:
                raise RuntimeError(reason)
            return self.state.generation

    def authorize_operation(self, envelope):
        with self.boundary("arm"):
            reason = self.state_reason()
            if reason:
                return fresh.FreshnessDecision("DENY", reason)
            try:
                authorization = sl.parse_arm_v2(envelope)
            except ValueError:
                return fresh.FreshnessDecision("DENY", "invalid_authorization")
            if not self.keyring.verify_arm_v2(authorization, expected_latch_id="latch"):
                return fresh.FreshnessDecision("DENY", "authentication_failed")
            if authorization.authorization_id in self.state.revoked:
                return fresh.FreshnessDecision("DENY", "authorization_revoked")
            # Linearization: result formed while STOP/revocation still excluded.
            return self.validator.validate(authorization)

    def stop(self):
        # Only a trusted supervisor invokes this; STOP authentication is not modeled.
        with self.boundary("stop"):
            reason = self.state_reason()
            if reason:
                return fresh.FreshnessDecision("DENY", reason)
            if self.state.generation == sl.ARM_V2_MAX_INTEGER:
                self.state.fault = "generation_exhausted"
                return fresh.FreshnessDecision("DENY", self.state.fault)
            self.state.generation += 1
            self.state.high_generation = self.state.generation
            return fresh.FreshnessDecision("ALLOW", "stop_generation_advanced")

    def revoke(self, authorization_id):
        with self.state.lock:
            self.state.revoked.add(authorization_id)

    def restart(self):
        return Authority(self.keyring, self.clock, self.state)


class Rig:
    def __init__(self):
        stop, legacy, self.arm = [Ed25519PrivateKey.generate() for _ in range(3)]

        def public(key):
            return key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )

        self.keyring = sl.ArmV2Keyring(
            {"stop": public(stop)}, {"legacy": public(legacy)},
            {"v2": sl.ArmV2VerificationKey("authority", "domain", public(self.arm))},
        )
        self.clock = Clock()
        self.authority = Authority(self.keyring, self.clock)

    def envelope(self, **changes):
        unsigned = sl.ArmV2Authorization(
            "latch", 1, "v2", "authority", "domain", "auth-1", 0, 100, 110,
            bytes(64),
        )
        unsigned = replace(unsigned, **changes)
        signed = replace(unsigned, signature=self.arm.sign(unsigned.signing_bytes()))
        return sl.arm_v2_envelope(signed)


@pytest.fixture
def rig():
    return Rig()


def assert_result(result, verdict, reason):
    assert result == fresh.FreshnessDecision(verdict, reason)


@contextmanager
def worker(call):
    results, errors = [], []

    def run():
        try:
            results.append(call())
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield results
    finally:
        thread.join(WATCHDOG)
        assert not thread.is_alive(), "worker failed to finish"
        if errors:
            raise errors[0]


@pytest.mark.parametrize("first", ["arm", "stop"])
def test_concurrent_lock_orders(rig, first):
    authority = rig.authority
    envelope = rig.envelope()
    calls = {"arm": lambda: authority.authorize_operation(envelope),
             "stop": authority.stop}
    second = "stop" if first == "arm" else "arm"
    authority.pause_kind = first
    authority.contender_kind = second
    with worker(calls[first]) as first_results:
        try:
            assert authority.entered.wait(WATCHDOG)
            with worker(calls[second]) as second_results:
                assert authority.contending.wait(WATCHDOG)
                assert first_results == second_results == []
                authority.release.set()
        finally:
            authority.release.set()
    arm_result = first_results[0] if first == "arm" else second_results[0]
    stop_result = second_results[0] if first == "arm" else first_results[0]
    assert_result(stop_result, "ALLOW", "stop_generation_advanced")
    assert_result(
        arm_result, "ALLOW" if first == "arm" else "DENY",
        "freshness_passed" if first == "arm" else "stop_generation_mismatch",
    )
    authority.pause_kind = authority.contender_kind = None
    assert authority.state.generation == 1
    assert_result(
        authority.authorize_operation(envelope), "DENY", "stop_generation_mismatch",
    )


def test_stop_before_check_and_fresh_reauthorization(rig):
    old = rig.envelope()
    assert_result(rig.authority.stop(), "ALLOW", "stop_generation_advanced")
    assert_result(
        rig.authority.authorize_operation(old), "DENY", "stop_generation_mismatch",
    )
    assert_result(
        rig.authority.authorize_operation(rig.envelope(stop_generation=1, authorization_id="new")),
        "ALLOW", "freshness_passed",
    )


def test_cached_allow_not_accepted_or_reusable_after_stop(rig):
    envelope = rig.envelope()
    cached = rig.authority.authorize_operation(envelope)
    assert_result(cached, "ALLOW", "freshness_passed")
    rig.authority.stop()
    assert_result(
        rig.authority.authorize_operation(cached), "DENY", "invalid_authorization",
    )
    assert_result(
        rig.authority.authorize_operation(envelope), "DENY", "stop_generation_mismatch",
    )
    assert cached.verdict == "ALLOW"  # Immutable historical result, not a live capability.


@pytest.mark.parametrize("before,after", [(0, 1), (1, 0), (0, 2**53)])
def test_wrong_generation(rig, before, after):
    rig.authority.state = State(after)
    rig.authority = rig.authority.restart()
    assert_result(
        rig.authority.authorize_operation(rig.envelope(stop_generation=before)),
        "DENY", "stop_generation_mismatch",
    )


@pytest.mark.parametrize("now,verdict,reason", [
    (99, "DENY", "authorization_premature"), (100, "ALLOW", "freshness_passed"),
    (109, "ALLOW", "freshness_passed"), (110, "DENY", "authorization_expired"),
    (111, "DENY", "authorization_expired"),
])
def test_time_boundaries(rig, now, verdict, reason):
    rig.clock.now = now
    assert_result(rig.authority.authorize_operation(rig.envelope()), verdict, reason)


@pytest.mark.parametrize("field,value", [
    ("signature", "0" * 128), ("not_after", 111),
    ("stop_generation", 1), ("authority_id", "other"), ("latch_id", "other"),
])
def test_forged_envelope(rig, field, value):
    forged = dict(rig.envelope(), **{field: value})
    assert_result(
        rig.authority.authorize_operation(forged), "DENY", "authentication_failed",
    )
    assert rig.authority.state.generation == 0


def test_invalid_envelope(rig):
    assert_result(rig.authority.authorize_operation({}), "DENY", "invalid_authorization")


def test_revoked_arm_and_restart(rig):
    envelope = rig.envelope()
    assert_result(rig.authority.authorize_operation(envelope), "ALLOW", "freshness_passed")
    rig.authority.revoke("auth-1")
    for authority in (rig.authority, rig.authority.restart()):
        assert_result(
            authority.authorize_operation(envelope), "DENY", "authorization_revoked",
        )


@pytest.mark.parametrize("clock_value", [None, True, 100.0, float("nan"), float("inf"), -1, 2**53 + 1])
def test_bad_clock_denies_arm_but_stop_works(rig, clock_value):
    rig.clock.now = clock_value
    assert_result(rig.authority.authorize_operation(rig.envelope()), "DENY", "invalid_clock")
    reads = rig.clock.calls
    assert_result(rig.authority.stop(), "ALLOW", "stop_generation_advanced")
    assert rig.clock.calls == reads


def test_throwing_clock_stop_and_restart(rig):
    envelope = rig.envelope()
    rig.clock.failure = True
    assert_result(rig.authority.authorize_operation(envelope), "DENY", "clock_unavailable")
    assert_result(rig.authority.stop(), "ALLOW", "stop_generation_advanced")
    rig.clock.failure = False
    assert_result(
        rig.authority.restart().authorize_operation(envelope), "DENY", "stop_generation_mismatch",
    )


def test_authority_failure_denies_both_and_does_not_advance(rig):
    rig.authority.state.unavailable = True
    assert_result(
        rig.authority.authorize_operation(rig.envelope()), "DENY", "authority_unavailable",
    )
    assert_result(rig.authority.stop(), "DENY", "authority_unavailable")
    assert rig.authority.state.generation == 0


def test_throwing_generation_provider_denies(rig, monkeypatch):
    def down():
        raise OSError("authority read failure")

    monkeypatch.setattr(rig.authority, "read", down)
    assert_result(
        rig.authority.authorize_operation(rig.envelope()), "DENY", "generation_unavailable",
    )
    assert_result(rig.authority.stop(), "ALLOW", "stop_generation_advanced")


def test_inconsistent_generation_state_denies(rig):
    rig.authority.state.generation = 1
    assert_result(
        rig.authority.authorize_operation(rig.envelope(stop_generation=1)),
        "DENY", "authority_state_inconsistent",
    )
    assert_result(rig.authority.stop(), "DENY", "authority_state_inconsistent")


def test_generation_rollback_sticky_across_reference_restart(rig):
    rig.authority.stop()
    rig.authority.state.generation = 0  # Fault injection, not an authority operation.
    assert_result(
        rig.authority.authorize_operation(rig.envelope()), "DENY", "generation_rollback",
    )
    rig.authority.state.generation = 1
    assert_result(rig.authority.restart().stop(), "DENY", "generation_rollback")


@pytest.mark.parametrize("value", [None, True, -1, 2**53 + 1])
def test_invalid_restart_state_denies(rig, value):
    rig.authority = Authority(rig.keyring, rig.clock, State(value))
    assert_result(
        rig.authority.authorize_operation(rig.envelope()), "DENY", "authority_state_invalid",
    )
    assert_result(rig.authority.stop(), "DENY", "authority_state_invalid")


def test_clock_rollback_preserved_with_retained_reference_state(rig):
    rig.clock.now = 105
    rig.authority.authorize_operation(rig.envelope())
    rig.clock.now = 100
    assert_result(
        rig.authority.restart().authorize_operation(rig.envelope()), "DENY", "clock_rollback",
    )
    assert_result(rig.authority.stop(), "ALLOW", "stop_generation_advanced")


def test_total_state_loss_cannot_detect_coherent_rollback(rig):
    old = rig.envelope()
    rig.authority.stop()
    assert_result(
        rig.authority.restart().authorize_operation(old), "DENY", "stop_generation_mismatch",
    )
    lost = Authority(rig.keyring, rig.clock, State())
    assert_result(lost.authorize_operation(old), "ALLOW", "freshness_passed")


def test_generation_exhaustion_fails_closed(rig):
    rig.authority = Authority(rig.keyring, rig.clock, State(2**53))
    assert_result(rig.authority.stop(), "DENY", "generation_exhausted")
    assert_result(
        rig.authority.authorize_operation(rig.envelope(stop_generation=2**53)),
        "DENY", "generation_exhausted",
    )


def test_same_generation_replay_still_passes_but_expiry_rechecked(rig):
    envelope = rig.envelope()
    for _ in range(2):
        assert_result(rig.authority.authorize_operation(envelope), "ALLOW", "freshness_passed")
    rig.clock.now = 110
    assert_result(
        rig.authority.authorize_operation(envelope), "DENY", "authorization_expired",
    )
