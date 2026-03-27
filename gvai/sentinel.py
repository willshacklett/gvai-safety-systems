from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Sequence

from gvai.metrics import RecoverabilitySignal, compute_recoverability_signal


@dataclass
class SentinelConfig:
    variance_threshold: float = 0.05
    drift_slope_threshold: float = 0.001
    collapse_threshold: float = 0.20
    critical_delta_t: float = 3.0
    warning_delta_t: float = 8.0


@dataclass
class SentinelEvent:
    step: int
    event_type: str
    message: str
    payload: Dict[str, object] = field(default_factory=dict)


@dataclass
class SentinelOutput:
    step: int
    variance_value: float
    variance_breach: bool
    drift_confirmed: bool
    drift_slope: float
    load_skew: float
    latency_skew: float
    recoverability_score: float
    status: str
    delta_t_estimate: Optional[float]
    recommended_action: str
    events: List[SentinelEvent]


class GVSentinel:
    """
    Runtime recoverability sentinel.

    This class turns raw node/system measurements into:
    - variance breach detection
    - drift confirmation
    - delta-t lead time estimate
    - recoverability state
    - recommended intervention action
    - structured events for dashboarding / hooks
    """

    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        self.config = config or SentinelConfig()
        self.step_count = 0
        self.variance_history: List[float] = []
        self.event_log: List[SentinelEvent] = []

    def reset(self) -> None:
        self.step_count = 0
        self.variance_history.clear()
        self.event_log.clear()

    def update(
        self,
        node_values: Sequence[float],
        load_values: Optional[Sequence[float]] = None,
        latency_values: Optional[Sequence[float]] = None,
    ) -> SentinelOutput:
        """
        Update the sentinel with a fresh system observation.

        Parameters
        ----------
        node_values:
            Per-node / per-shard / per-service scalar values.
            These are the values whose dispersion is being monitored.
        load_values:
            Optional load vector for skew detection.
        latency_values:
            Optional latency vector for skew detection.
        """
        # first pass: use current known history
        preliminary = compute_recoverability_signal(
            node_values=node_values,
            variance_history=self.variance_history,
            load_values=load_values,
            latency_values=latency_values,
            variance_threshold=self.config.variance_threshold,
            drift_slope_threshold=self.config.drift_slope_threshold,
            collapse_threshold=self.config.collapse_threshold,
        )

        # append observed variance for future drift estimation
        self.variance_history.append(preliminary.variance_value)

        # second pass: now include latest variance in history
        signal = compute_recoverability_signal(
            node_values=node_values,
            variance_history=self.variance_history,
            load_values=load_values,
            latency_values=latency_values,
            variance_threshold=self.config.variance_threshold,
            drift_slope_threshold=self.config.drift_slope_threshold,
            collapse_threshold=self.config.collapse_threshold,
        )

        events = self._build_events(signal)
        action = self._recommend_action(signal)

        output = SentinelOutput(
            step=self.step_count,
            variance_value=signal.variance_value,
            variance_breach=signal.variance_breach,
            drift_confirmed=signal.drift.drift_confirmed,
            drift_slope=signal.drift.slope,
            load_skew=signal.load_skew,
            latency_skew=signal.latency_skew,
            recoverability_score=signal.recoverability_score,
            status=self._status_override(signal, action),
            delta_t_estimate=signal.delta_t_estimate,
            recommended_action=action,
            events=events,
        )

        self.step_count += 1
        return output

    def _build_events(self, signal: RecoverabilitySignal) -> List[SentinelEvent]:
        events: List[SentinelEvent] = []

        if signal.variance_breach:
            events.append(
                self._emit(
                    "breach",
                    "Variance breached sentinel threshold.",
                    {
                        "variance_value": signal.variance_value,
                        "threshold": self.config.variance_threshold,
                    },
                )
            )

        if signal.drift.drift_confirmed:
            events.append(
                self._emit(
                    "drift_confirm",
                    "Variance drift confirmed.",
                    {
                        "drift_slope": signal.drift.slope,
                        "drift_mean": signal.drift.mean,
                    },
                )
            )

        if signal.delta_t_estimate is not None:
            events.append(
                self._emit(
                    "delta_t",
                    "Estimated intervention lead time updated.",
                    {
                        "delta_t_estimate": signal.delta_t_estimate,
                        "collapse_threshold": self.config.collapse_threshold,
                    },
                )
            )

        if signal.status in ("critical", "irrecoverable"):
            events.append(
                self._emit(
                    "status",
                    f"Recoverability status is {signal.status}.",
                    {
                        "status": signal.status,
                        "recoverability_score": signal.recoverability_score,
                    },
                )
            )

        return events

    def _recommend_action(self, signal: RecoverabilitySignal) -> str:
        """
        Extremely simple action policy for now.
        This is intentionally interpretable.
        """
        if signal.status == "irrecoverable":
            return "isolate"

        if signal.load_skew >= 0.75:
            return "rebalance"

        if signal.latency_skew >= 0.50:
            return "rebalance"

        if signal.variance_breach and signal.drift.drift_confirmed:
            if signal.delta_t_estimate is not None and signal.delta_t_estimate <= self.config.critical_delta_t:
                return "damp"
            return "rebalance"

        if signal.variance_breach:
            return "damp"

        return "none"

    def _status_override(self, signal: RecoverabilitySignal, action: str) -> str:
        """
        Optionally tighten status when delta-t is very short even if the
        raw score has not yet crossed a threshold.
        """
        if signal.delta_t_estimate is not None:
            if signal.delta_t_estimate <= self.config.critical_delta_t:
                return "critical"
            if signal.delta_t_estimate <= self.config.warning_delta_t and signal.status == "stable":
                return "warning"

        if action == "isolate":
            return "irrecoverable"

        return signal.status

    def _emit(self, event_type: str, message: str, payload: Dict[str, object]) -> SentinelEvent:
        evt = SentinelEvent(
            step=self.step_count,
            event_type=event_type,
            message=message,
            payload=payload,
        )
        self.event_log.append(evt)
        return evt


def output_to_dict(output: SentinelOutput) -> Dict[str, object]:
    return {
        "step": output.step,
        "variance_value": output.variance_value,
        "variance_breach": output.variance_breach,
        "drift_confirmed": output.drift_confirmed,
        "drift_slope": output.drift_slope,
        "load_skew": output.load_skew,
        "latency_skew": output.latency_skew,
        "recoverability_score": output.recoverability_score,
        "status": output.status,
        "delta_t_estimate": output.delta_t_estimate,
        "recommended_action": output.recommended_action,
        "events": [
            {
                "step": e.step,
                "event_type": e.event_type,
                "message": e.message,
                "payload": e.payload,
            }
            for e in output.events
        ],
    }


if __name__ == "__main__":
    sentinel = GVSentinel()

    frames = [
        {
            "node_values": [1.00, 1.02, 0.99, 1.01, 1.00, 0.98],
            "load_values": [10, 11, 10, 11, 10, 9],
            "latency_values": [100, 102, 99, 101, 100, 98],
        },
        {
            "node_values": [1.00, 1.05, 0.97, 1.08, 1.12, 0.95],
            "load_values": [10, 11, 10, 13, 15, 9],
            "latency_values": [101, 103, 100, 106, 112, 99],
        },
        {
            "node_values": [1.00, 1.15, 0.90, 1.22, 1.35, 0.82],
            "load_values": [10, 11, 10, 15, 22, 8],
            "latency_values": [100, 105, 101, 115, 135, 99],
        },
        {
            "node_values": [1.00, 1.30, 0.75, 1.42, 1.70, 0.60],
            "load_values": [10, 11, 10, 16, 28, 8],
            "latency_values": [102, 108, 100, 125, 150, 98],
        },
    ]

    for i, frame in enumerate(frames):
        out = sentinel.update(
            node_values=frame["node_values"],
            load_values=frame["load_values"],
            latency_values=frame["latency_values"],
        )
        print(f"\nSTEP {i}")
        print("VARIANCE:", out.variance_value)
        print("BREACH:", out.variance_breach)
        print("DRIFT:", out.drift_confirmed)
        print("DRIFT SLOPE:", out.drift_slope)
        print("LOAD SKEW:", out.load_skew)
        print("LATENCY SKEW:", out.latency_skew)
        print("SCORE:", out.recoverability_score)
        print("STATUS:", out.status)
        print("DELTA_T:", out.delta_t_estimate)
        print("ACTION:", out.recommended_action)
        print("EVENTS:", [e.event_type for e in out.events])
