from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from gvai.interventions import InterventionResult, apply_action
from gvai.metrics import RecoverabilitySignal, compute_recoverability_signal


@dataclass
class SentinelConfig:
    variance_threshold: float = 0.05
    drift_slope_threshold: float = 0.001
    collapse_threshold: float = 0.20
    critical_delta_t: float = 3.0
    warning_delta_t: float = 8.0
    auto_apply: bool = False
    rebalance_strength: float = 0.50
    damp_strength: float = 0.35
    isolate_indices: Optional[List[int]] = None
    isolate_replacement: Optional[float] = None


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
    applied: bool
    intervention: Optional[InterventionResult]
    post_action_values: Optional[List[float]]
    events: List[SentinelEvent]


class GVSentinel:
    """
    Runtime recoverability sentinel.

    observe -> detect -> classify -> recommend -> optionally act
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
        preliminary = compute_recoverability_signal(
            node_values=node_values,
            variance_history=self.variance_history,
            load_values=load_values,
            latency_values=latency_values,
            variance_threshold=self.config.variance_threshold,
            drift_slope_threshold=self.config.drift_slope_threshold,
            collapse_threshold=self.config.collapse_threshold,
        )

        self.variance_history.append(preliminary.variance_value)

        signal = compute_recoverability_signal(
            node_values=node_values,
            variance_history=self.variance_history,
            load_values=load_values,
            latency_values=latency_values,
            variance_threshold=self.config.variance_threshold,
            drift_slope_threshold=self.config.drift_slope_threshold,
            collapse_threshold=self.config.collapse_threshold,
        )

        action = self._recommend_action(signal)
        status = self._status_override(signal, action)
        events = self._build_events(signal, status, action)

        applied = False
        intervention: Optional[InterventionResult] = None
        post_action_values: Optional[List[float]] = None

        if self.config.auto_apply and action != "none":
            intervention = apply_action(
                action,
                node_values,
                rebalance_strength=self.config.rebalance_strength,
                damp_strength=self.config.damp_strength,
                isolate_indices=self.config.isolate_indices or [],
                isolate_replacement=self.config.isolate_replacement,
            )
            post_action_values = intervention.after
            applied = True
            events.append(
                self._emit(
                    "act",
                    f"Applied intervention: {action}.",
                    {
                        "action": action,
                        "changed_indices": intervention.changed_indices,
                        "note": intervention.note,
                    },
                )
            )

        output = SentinelOutput(
            step=self.step_count,
            variance_value=signal.variance_value,
            variance_breach=signal.variance_breach,
            drift_confirmed=signal.drift.drift_confirmed,
            drift_slope=signal.drift.slope,
            load_skew=signal.load_skew,
            latency_skew=signal.latency_skew,
            recoverability_score=signal.recoverability_score,
            status=status,
            delta_t_estimate=signal.delta_t_estimate,
            recommended_action=action,
            applied=applied,
            intervention=intervention,
            post_action_values=post_action_values,
            events=events,
        )

        self.step_count += 1
        return output

    def _build_events(
        self,
        signal: RecoverabilitySignal,
        status: str,
        action: str,
    ) -> List[SentinelEvent]:
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

        if status in ("critical", "irrecoverable", "warning"):
            events.append(
                self._emit(
                    "status",
                    f"Recoverability status is {status}.",
                    {
                        "status": status,
                        "recoverability_score": signal.recoverability_score,
                    },
                )
            )

        if action != "none":
            events.append(
                self._emit(
                    "recommend",
                    f"Recommended action: {action}.",
                    {"action": action},
                )
            )

        return events

    def _recommend_action(self, signal: RecoverabilitySignal) -> str:
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
        "applied": output.applied,
        "post_action_values": output.post_action_values,
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
    print("=== MANUAL MODE ===")
    manual = GVSentinel(
        SentinelConfig(
            auto_apply=False,
            critical_delta_t=3.0,
            warning_delta_t=8.0,
        )
    )

    print("=== AUTO-APPLY MODE ===")
    auto = GVSentinel(
        SentinelConfig(
            auto_apply=True,
            critical_delta_t=3.0,
            warning_delta_t=8.0,
            rebalance_strength=0.50,
            damp_strength=0.35,
            isolate_indices=[4, 5],
        )
    )

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

    print("\n--- MANUAL RECOMMENDATIONS ---")
    for i, frame in enumerate(frames):
        out = manual.update(
            node_values=frame["node_values"],
            load_values=frame["load_values"],
            latency_values=frame["latency_values"],
        )
        print(f"\nSTEP {i}")
        print("STATUS:", out.status)
        print("DELTA_T:", out.delta_t_estimate)
        print("ACTION:", out.recommended_action)
        print("APPLIED:", out.applied)
        print("EVENTS:", [e.event_type for e in out.events])

    print("\n--- AUTO-APPLY ---")
    for i, frame in enumerate(frames):
        out = auto.update(
            node_values=frame["node_values"],
            load_values=frame["load_values"],
            latency_values=frame["latency_values"],
        )
        print(f"\nSTEP {i}")
        print("STATUS:", out.status)
        print("DELTA_T:", out.delta_t_estimate)
        print("ACTION:", out.recommended_action)
        print("APPLIED:", out.applied)
        if out.intervention is not None:
            print("INTERVENTION NOTE:", out.intervention.note)
            print("POST ACTION VALUES:", out.post_action_values)
        print("EVENTS:", [e.event_type for e in out.events])
