from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from gvai.interventions import InterventionResult, apply_action
from gvai.metrics import RecoverabilitySignal, compute_recoverability_signal
from gvai.metrics_v2 import GVTrendTracker


@dataclass
class SentinelConfig:
    variance_threshold: float = 0.05
    drift_slope_threshold: float = 0.001
    collapse_threshold: float = 0.20
    critical_delta_t: float = 3.0
    warning_delta_t: float = 8.0

    velocity_window: int = 8
    variance_velocity_threshold: float = 0.02
    variance_acceleration_threshold: float = 0.02
    dt_stagnation_threshold: float = 0.02

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
    variance_velocity: float
    variance_acceleration: float
    dt_stagnation: float
    soft_regime_flag: bool
    events: List[SentinelEvent]


class GVSentinel:
    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        self.config = config or SentinelConfig()
        self.step_count = 0
        self.variance_history: List[float] = []
        self.event_log: List[SentinelEvent] = []
        self.tracker = GVTrendTracker(window=self.config.velocity_window)

    def reset(self) -> None:
        self.step_count = 0
        self.variance_history.clear()
        self.event_log.clear()
        self.tracker = GVTrendTracker(window=self.config.velocity_window)

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

        self.tracker.update(signal.variance_value, signal.delta_t_estimate)
        var_vel = self.tracker.variance_velocity()
        var_acc = self.tracker.variance_acceleration()
        dt_stag = self.tracker.dt_stagnation()

        irrecoverable_by_accel = var_acc > self.config.variance_acceleration_threshold
        soft_regime = (
            not signal.variance_breach
            and var_vel > self.config.variance_velocity_threshold
            and dt_stag < self.config.dt_stagnation_threshold
            and not irrecoverable_by_accel
        )

        action = self._recommend_action(signal, soft_regime, irrecoverable_by_accel)
        status = self._status_override(signal, action, soft_regime, irrecoverable_by_accel)
        events = self._build_events(signal, status, action, soft_regime, irrecoverable_by_accel, var_vel, var_acc, dt_stag)

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

        out = SentinelOutput(
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
            variance_velocity=var_vel,
            variance_acceleration=var_acc,
            dt_stagnation=dt_stag,
            soft_regime_flag=soft_regime,
            events=events,
        )

        self.step_count += 1
        return out

    def _build_events(
        self,
        signal: RecoverabilitySignal,
        status: str,
        action: str,
        soft_regime: bool,
        irrecoverable_by_accel: bool,
        var_vel: float,
        var_acc: float,
        dt_stag: float,
    ) -> List[SentinelEvent]:
        events: List[SentinelEvent] = []

        if signal.variance_breach:
            events.append(self._emit("breach", "Variance breached threshold.", {"variance_value": signal.variance_value}))

        if signal.drift.drift_confirmed:
            events.append(self._emit("drift_confirm", "Variance drift confirmed.", {"drift_slope": signal.drift.slope}))

        if signal.delta_t_estimate is not None:
            events.append(self._emit("delta_t", "Lead time updated.", {"delta_t_estimate": signal.delta_t_estimate}))

        if var_vel > self.config.variance_velocity_threshold:
            events.append(self._emit("var_velocity", "Variance velocity exceeded threshold.", {"variance_velocity": var_vel}))

        if var_acc > self.config.variance_acceleration_threshold:
            events.append(self._emit("var_acceleration", "Variance acceleration exceeded threshold.", {"variance_acceleration": var_acc}))

        if dt_stag < self.config.dt_stagnation_threshold:
            events.append(self._emit("dt_stagnation", "Δt stagnation detected.", {"dt_stagnation": dt_stag}))

        if soft_regime:
            events.append(self._emit("soft_regime", "Low-signal degradation regime flagged.", {}))

        if irrecoverable_by_accel:
            events.append(self._emit("irrecoverable_accel", "Runaway acceleration detected.", {}))

        if status in ("warning", "critical", "irrecoverable"):
            events.append(self._emit("status", f"Recoverability status is {status}.", {"status": status}))

        if action != "none":
            events.append(self._emit("recommend", f"Recommended action: {action}.", {"action": action}))

        return events

    def _recommend_action(self, signal: RecoverabilitySignal, soft_regime: bool, irrecoverable_by_accel: bool) -> str:
        if irrecoverable_by_accel or signal.status == "irrecoverable":
            return "isolate"

        if soft_regime:
            return "damp"

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

    def _status_override(
        self,
        signal: RecoverabilitySignal,
        action: str,
        soft_regime: bool,
        irrecoverable_by_accel: bool,
    ) -> str:
        if irrecoverable_by_accel or action == "isolate":
            return "irrecoverable"

        if signal.delta_t_estimate is not None:
            if signal.delta_t_estimate <= self.config.critical_delta_t:
                return "critical"
            if signal.delta_t_estimate <= self.config.warning_delta_t and signal.status == "stable":
                return "warning"

        if soft_regime and signal.status == "stable":
            return "warning"

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
