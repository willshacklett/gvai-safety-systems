"""Isolated freshness checks; neither authentication nor execution permission."""

from dataclasses import dataclass, replace
from threading import Lock
from typing import Protocol

from gvai.experimental_stop_latch import ARM_V2_MAX_INTEGER, ArmV2Authorization


class TrustedClock(Protocol):
    def read(self) -> int: ...


class StopGenerationAuthority(Protocol):
    """Configured supervisor authority, never a value supplied with a request."""

    def read(self) -> int: ...


class TrustedClockHighWater(Protocol):
    """Atomically observe time; false means rollback, including a sticky fault.

    Implementations must validate their stored state and raise if unavailable
    or corrupt. True means the sample is at least the previous high-water mark
    and has been recorded. Independence/durability is a deployment obligation.
    """

    def observe(self, now: int) -> bool: ...


def _valid_integer(value: object) -> bool:
    return type(value) is int and 0 <= value <= ARM_V2_MAX_INTEGER


class VolatileClockHighWater:
    """In-process reference only. Losing this object loses rollback history."""

    def __init__(self, initial: int) -> None:
        if not _valid_integer(initial):
            raise ValueError("invalid_initial_high_water")
        self._high_water = initial
        self._rollback = False
        self._lock = Lock()

    def observe(self, now: int) -> bool:
        if not _valid_integer(now):
            raise ValueError("invalid_clock_sample")
        with self._lock:
            if not _valid_integer(self._high_water) or type(self._rollback) is not bool:
                raise ValueError("invalid_high_water_state")
            if now < self._high_water:
                self._rollback = True
            if self._rollback:
                return False
            self._high_water = now
            return True


@dataclass(frozen=True)
class FreshnessDecision:
    """ALLOW means only that freshness checks passed at the sampled inputs."""

    verdict: str
    reason: str


class ArmV2FreshnessValidator:
    """Call only after Stage A authentication under the configured trust policy.

    Providers must be selected by the trusted supervisor, not the requestor.
    This API cannot establish provider independence or prove prior authentication.
    """

    def __init__(
        self, *, clock: TrustedClock, generations: StopGenerationAuthority,
        high_water: TrustedClockHighWater,
    ) -> None:
        for provider, method in (
            (clock, "read"), (generations, "read"), (high_water, "observe"),
        ):
            if not callable(getattr(provider, method, None)):
                raise ValueError("invalid_trusted_provider")
        self._clock = clock
        self._generations = generations
        self._high_water = high_water
        self._rollback = False
        self._lock = Lock()

    def validate(self, authorization: ArmV2Authorization) -> FreshnessDecision:
        """No request-side clock/generation overrides; no consumption of identity."""
        if type(authorization) is not ArmV2Authorization:
            return FreshnessDecision("DENY", "invalid_authorization")
        try:
            # Snapshot and revalidate structural invariants, not the signature.
            authorization = replace(authorization)
        except (ValueError, TypeError, AttributeError):
            return FreshnessDecision("DENY", "invalid_authorization")
        with self._lock:
            if self._rollback:
                return FreshnessDecision("DENY", "clock_rollback")
            try:
                now = self._clock.read()
            except Exception:
                return FreshnessDecision("DENY", "clock_unavailable")
            if not _valid_integer(now):
                return FreshnessDecision("DENY", "invalid_clock")
            try:
                observed = self._high_water.observe(now)
            except Exception:
                return FreshnessDecision("DENY", "high_water_unavailable")
            if type(observed) is not bool:
                return FreshnessDecision("DENY", "invalid_high_water_result")
            if not observed:
                self._rollback = True
                return FreshnessDecision("DENY", "clock_rollback")
            try:
                generation = self._generations.read()
            except Exception:
                return FreshnessDecision("DENY", "generation_unavailable")
            if not _valid_integer(generation):
                return FreshnessDecision("DENY", "invalid_generation")
            if authorization.stop_generation != generation:
                return FreshnessDecision("DENY", "stop_generation_mismatch")
            if now < authorization.not_before:
                return FreshnessDecision("DENY", "authorization_premature")
            if now >= authorization.not_after:
                return FreshnessDecision("DENY", "authorization_expired")
            return FreshnessDecision("ALLOW", "freshness_passed")
