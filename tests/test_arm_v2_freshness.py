"""Injected trusted inputs, no wall-clock sleeps, persistence or live wiring."""

from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gvai import arm_v2_freshness as fresh
from gvai import experimental_stop_latch as sl


class Provider:
    def __init__(self, value):
        self.value = value
        self.failure = None
        self.calls = 0

    def read(self):
        self.calls += 1
        if self.failure:
            raise self.failure
        return self.value


@pytest.fixture
def authorization():
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]

    def public(key):
        return key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    ring = sl.ArmV2Keyring(
        {"stop": public(keys[0])}, {"legacy": public(keys[1])},
        {"v2": sl.ArmV2VerificationKey("authority", "domain", public(keys[2]))},
    )
    unsigned = sl.ArmV2Authorization(
        "latch", 1, "v2", "authority", "domain", "auth-1", 0, 100, 110, bytes(64),
    )
    signed = replace(unsigned, signature=keys[2].sign(unsigned.signing_bytes()))
    parsed = sl.parse_arm_v2(sl.arm_v2_envelope(signed))
    assert ring.verify_arm_v2(parsed, expected_latch_id="latch")
    return parsed


def validator(now=100, generation=0, initial=0):
    clock, generations = Provider(now), Provider(generation)
    mark = fresh.VolatileClockHighWater(initial)
    check = fresh.ArmV2FreshnessValidator(
        clock=clock, generations=generations, high_water=mark,
    )
    return check, clock, generations, mark


def assert_decision(check, authorization, verdict, reason):
    assert check.validate(authorization) == fresh.FreshnessDecision(verdict, reason)


@pytest.mark.parametrize("now,verdict,reason", [
    (99, "DENY", "authorization_premature"),
    (100, "ALLOW", "freshness_passed"),
    (109, "ALLOW", "freshness_passed"),
    (110, "DENY", "authorization_expired"),
    (111, "DENY", "authorization_expired"),
])
def test_half_open_boundaries(authorization, now, verdict, reason):
    assert_decision(validator(now)[0], authorization, verdict, reason)


INVALID = [None, True, False, "100", b"100", [], {}, -1, 2**53 + 1,
           100.0, 100.5, float("nan"), float("inf"), float("-inf")]


@pytest.mark.parametrize("value", INVALID)
def test_invalid_clock(authorization, value):
    assert_decision(validator(value)[0], authorization, "DENY", "invalid_clock")


@pytest.mark.parametrize("value", INVALID)
def test_invalid_generation(authorization, value):
    assert_decision(
        validator(generation=value)[0], authorization, "DENY", "invalid_generation",
    )


@pytest.mark.parametrize("current,signed", [(1, 0), (0, 1), (2**53, 0)])
def test_old_and_future_generations_deny(authorization, current, signed):
    assert_decision(
        validator(generation=current)[0],
        replace(authorization, stop_generation=signed),
        "DENY", "stop_generation_mismatch",
    )


def test_generation_read_from_authority_on_every_check(authorization):
    check, clock, generations, _ = validator()
    assert_decision(check, authorization, "ALLOW", "freshness_passed")
    generations.value = 1
    assert_decision(check, authorization, "DENY", "stop_generation_mismatch")
    assert generations.calls == 2
    assert clock.calls == 2
    with pytest.raises(TypeError):
        check.validate(authorization, current_generation=0)
    with pytest.raises(TypeError):
        check.validate(authorization, now=100)


@pytest.mark.parametrize("provider,reason", [
    ("clock", "clock_unavailable"), ("generation", "generation_unavailable"),
])
def test_provider_failure_and_explicit_recovery(authorization, provider, reason):
    check, clock, generations, _ = validator()
    failing = clock if provider == "clock" else generations
    failing.failure = RuntimeError("private provider detail")
    assert_decision(check, authorization, "DENY", reason)
    failing.failure = None
    assert_decision(check, authorization, "ALLOW", "freshness_passed")


def test_clock_rollback_sticky_even_when_time_recovers(authorization):
    check, clock, _, _ = validator()
    assert_decision(check, authorization, "ALLOW", "freshness_passed")
    clock.value = 99
    assert_decision(check, authorization, "DENY", "clock_rollback")
    clock.value = 105
    assert_decision(check, authorization, "DENY", "clock_rollback")


def test_independent_initial_high_water_and_equal_samples(authorization):
    assert_decision(validator(initial=101)[0], authorization, "DENY", "clock_rollback")
    check = validator(initial=100)[0]
    for _ in range(2):
        assert_decision(check, authorization, "ALLOW", "freshness_passed")


def test_denied_request_still_advances_clock_high_water(authorization):
    check, clock, _, _ = validator(110)
    assert_decision(check, authorization, "DENY", "authorization_expired")
    clock.value = 109
    assert_decision(check, authorization, "DENY", "clock_rollback")


def test_shared_mark_and_restart_limitation(authorization):
    check, clock, generations, mark = validator(105)
    assert_decision(check, authorization, "ALLOW", "freshness_passed")
    clock.value = 100
    restarted = fresh.ArmV2FreshnessValidator(
        clock=clock, generations=generations, high_water=mark,
    )
    assert_decision(restarted, authorization, "DENY", "clock_rollback")
    # A fresh volatile mark has no evidence of the old 105 reading.
    assert_decision(validator(100)[0], authorization, "ALLOW", "freshness_passed")
    clock.value = 106
    another = fresh.ArmV2FreshnessValidator(
        clock=clock, generations=generations, high_water=mark,
    )
    assert_decision(another, authorization, "DENY", "clock_rollback")


@pytest.mark.parametrize("result", [None, 1, "true", []])
def test_invalid_high_water_result(authorization, result):
    class BadMark:
        def observe(self, now):
            return result

    check = fresh.ArmV2FreshnessValidator(
        clock=Provider(100), generations=Provider(0), high_water=BadMark(),
    )
    assert_decision(check, authorization, "DENY", "invalid_high_water_result")


def test_high_water_provider_failure(authorization):
    class DownMark:
        def observe(self, now):
            raise OSError("trusted state unavailable")

    check = fresh.ArmV2FreshnessValidator(
        clock=Provider(100), generations=Provider(0), high_water=DownMark(),
    )
    assert_decision(check, authorization, "DENY", "high_water_unavailable")


@pytest.mark.parametrize("value", INVALID)
def test_corrupt_reference_high_water_denies(authorization, value):
    check, _, _, mark = validator()
    mark._high_water = value
    assert_decision(check, authorization, "DENY", "high_water_unavailable")


def test_reference_rejects_invalid_sample():
    with pytest.raises(ValueError, match="invalid_clock_sample"):
        fresh.VolatileClockHighWater(0).observe(True)


@pytest.mark.parametrize("value", INVALID)
def test_invalid_initial_high_water(value):
    with pytest.raises(ValueError, match="invalid_initial_high_water"):
        fresh.VolatileClockHighWater(value)


@pytest.mark.parametrize("provider", ["clock", "generations", "high_water"])
def test_missing_provider_is_configuration_error(provider):
    options = dict(clock=Provider(100), generations=Provider(0),
                   high_water=fresh.VolatileClockHighWater(0))
    options[provider] = None
    with pytest.raises(ValueError, match="invalid_trusted_provider"):
        fresh.ArmV2FreshnessValidator(**options)


@pytest.mark.parametrize("value", [None, {}, "arm"])
def test_invalid_authorization(value):
    assert_decision(validator()[0], value, "DENY", "invalid_authorization")


def test_mutated_authorization_and_subclass_rejected(authorization):
    mutated = replace(authorization)
    object.__setattr__(mutated, "not_after", float("nan"))
    assert_decision(validator()[0], mutated, "DENY", "invalid_authorization")

    class Derived(sl.ArmV2Authorization):
        pass

    derived = Derived(**vars(authorization))
    assert_decision(validator()[0], derived, "DENY", "invalid_authorization")


def test_replay_and_authenticity_are_not_freshness_enforcement(authorization):
    check = validator()[0]
    for _ in range(2):
        assert_decision(check, authorization, "ALLOW", "freshness_passed")
    # Preauthentication is a caller obligation: no signature checking here.
    forged = replace(authorization, signature=bytes(64))
    assert_decision(check, forged, "ALLOW", "freshness_passed")


def test_maximum_time_and_generation(authorization):
    auth = replace(
        authorization, not_before=2**53 - 1, not_after=2**53,
        stop_generation=2**53,
    )
    assert_decision(
        validator(2**53 - 1, 2**53)[0], auth, "ALLOW", "freshness_passed",
    )
    assert_decision(
        validator(2**53, 2**53)[0], auth, "DENY", "authorization_expired",
    )
