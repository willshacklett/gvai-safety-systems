from __future__ import annotations

from dataclasses import dataclass
from statistics import mean
from typing import List, Optional, Sequence


def safe_mean(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def variance(values: Sequence[float]) -> float:
    """
    Population variance.
    Returns 0.0 for empty or singleton inputs.
    """
    n = len(values)
    if n <= 1:
        return 0.0
    mu = safe_mean(values)
    return sum((x - mu) ** 2 for x in values) / n


def stddev(values: Sequence[float]) -> float:
    return variance(values) ** 0.5


def slope(values: Sequence[float]) -> float:
    """
    Simple least-squares slope against x = [0, 1, ..., n-1].
    Returns 0.0 for short inputs.
    """
    n = len(values)
    if n <= 1:
        return 0.0

    x_mu = (n - 1) / 2.0
    y_mu = safe_mean(values)

    num = 0.0
    den = 0.0
    for i, y in enumerate(values):
        dx = i - x_mu
        num += dx * (y - y_mu)
        den += dx * dx

    if den == 0:
        return 0.0
    return num / den


@dataclass
class RollingWindow:
    size: int
    values: List[float]

    def __init__(self, size: int) -> None:
        if size <= 0:
            raise ValueError("size must be > 0")
        self.size = size
        self.values = []

    def append(self, value: float) -> None:
        self.values.append(float(value))
        if len(self.values) > self.size:
            self.values.pop(0)

    def extend(self, items: Sequence[float]) -> None:
        for item in items:
            self.append(float(item))

    def clear(self) -> None:
        self.values.clear()

    def full(self) -> bool:
        return len(self.values) >= self.size

    def latest(self) -> float:
        if not self.values:
            return 0.0
        return self.values[-1]

    def mean(self) -> float:
        return safe_mean(self.values)

    def variance(self) -> float:
        return variance(self.values)

    def stddev(self) -> float:
        return stddev(self.values)

    def slope(self) -> float:
        return slope(self.values)

    def as_list(self) -> List[float]:
        return list(self.values)


@dataclass
class DriftSignal:
    slope: float
    mean: float
    variance: float
    drift_confirmed: bool


@dataclass
class RecoverabilitySignal:
    variance_value: float
    variance_breach: bool
    drift: DriftSignal
    load_skew: float
    latency_skew: float
    recoverability_score: float
    status: str
    delta_t_estimate: Optional[float]


def variance_breach(
    node_values: Sequence[float],
    threshold: float,
) -> bool:
    return variance(node_values) >= threshold


def drift_confirm(
    history: Sequence[float],
    slope_threshold: float = 0.0,
    min_points: int = 4,
) -> DriftSignal:
    vals = list(history)
    s = slope(vals)
    m = safe_mean(vals)
    v = variance(vals)
    confirmed = len(vals) >= min_points and s > slope_threshold
    return DriftSignal(
        slope=s,
        mean=m,
        variance=v,
        drift_confirmed=confirmed,
    )


def normalized_skew(values: Sequence[float]) -> float:
    """
    Simple skew proxy:
        (max - mean) / mean

    Returns 0.0 if mean <= 0 or input empty.
    """
    if not values:
        return 0.0
    m = safe_mean(values)
    if m <= 0:
        return 0.0
    return max(0.0, (max(values) - m) / m)


def recoverability_score(
    variance_value: float,
    drift_slope: float,
    load_skew: float,
    latency_skew: float,
    variance_weight: float = 0.35,
    drift_weight: float = 0.30,
    load_weight: float = 0.20,
    latency_weight: float = 0.15,
) -> float:
    """
    Returns a score in [0, 1], where:
      1.0 = highly recoverable
      0.0 = effectively unrecoverable

    This is intentionally simple and interpretable for now.
    """
    penalty = (
        variance_weight * max(0.0, variance_value)
        + drift_weight * max(0.0, drift_slope)
        + load_weight * max(0.0, load_skew)
        + latency_weight * max(0.0, latency_skew)
    )
    score = 1.0 - penalty
    return max(0.0, min(1.0, score))


def recoverability_status(
    score: float,
    critical_cutoff: float = 0.35,
    warning_cutoff: float = 0.65,
    irrecoverable_cutoff: float = 0.10,
) -> str:
    if score <= irrecoverable_cutoff:
        return "irrecoverable"
    if score <= critical_cutoff:
        return "critical"
    if score <= warning_cutoff:
        return "warning"
    return "stable"


def estimate_delta_t(
    current_variance: float,
    variance_slope: float,
    collapse_threshold: float,
) -> Optional[float]:
    """
    Rough lead-time estimate:
        Δt ≈ (collapse_threshold - current_variance) / variance_slope

    Returns None when the slope is non-positive or already beyond threshold.
    """
    if current_variance >= collapse_threshold:
        return 0.0
    if variance_slope <= 0:
        return None
    return max(0.0, (collapse_threshold - current_variance) / variance_slope)


def compute_recoverability_signal(
    node_values: Sequence[float],
    variance_history: Sequence[float],
    load_values: Optional[Sequence[float]] = None,
    latency_values: Optional[Sequence[float]] = None,
    variance_threshold: float = 0.05,
    drift_slope_threshold: float = 0.001,
    collapse_threshold: float = 0.20,
) -> RecoverabilitySignal:
    current_variance = variance(node_values)
    breach = current_variance >= variance_threshold

    drift = drift_confirm(
        variance_history,
        slope_threshold=drift_slope_threshold,
        min_points=4,
    )

    load = normalized_skew(load_values or [])
    latency = normalized_skew(latency_values or [])

    score = recoverability_score(
        variance_value=current_variance,
        drift_slope=drift.slope,
        load_skew=load,
        latency_skew=latency,
    )
    status = recoverability_status(score)

    dt = estimate_delta_t(
        current_variance=current_variance,
        variance_slope=drift.slope,
        collapse_threshold=collapse_threshold,
    )

    return RecoverabilitySignal(
        variance_value=current_variance,
        variance_breach=breach,
        drift=drift,
        load_skew=load,
        latency_skew=latency,
        recoverability_score=score,
        status=status,
        delta_t_estimate=dt,
    )


if __name__ == "__main__":
    node_values = [1.0, 1.1, 0.9, 1.2, 2.0, 0.8]
    variance_history = [0.01, 0.02, 0.03, 0.05, 0.08, 0.12]
    load_values = [10, 11, 10, 12, 25, 9]
    latency_values = [100, 103, 98, 102, 145, 99]

    signal = compute_recoverability_signal(
        node_values=node_values,
        variance_history=variance_history,
        load_values=load_values,
        latency_values=latency_values,
        variance_threshold=0.05,
        drift_slope_threshold=0.005,
        collapse_threshold=0.20,
    )

    print("VARIANCE:", signal.variance_value)
    print("BREACH:", signal.variance_breach)
    print("DRIFT SLOPE:", signal.drift.slope)
    print("DRIFT CONFIRMED:", signal.drift.drift_confirmed)
    print("LOAD SKEW:", signal.load_skew)
    print("LATENCY SKEW:", signal.latency_skew)
    print("RECOVERABILITY SCORE:", signal.recoverability_score)
    print("STATUS:", signal.status)
    print("DELTA_T:", signal.delta_t_estimate)
