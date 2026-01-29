from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, Literal

from .signals import RuntimeSignals

RiskBand = Literal["green", "yellow", "red"]
Action = Literal["continue", "slow", "halt"]


@dataclass
class GuardConfig:
    """
    Tunable parameters for the GV runtime guard.

    Defaults are conservative and designed to be stable and predictable.
    """
    # Base dynamics
    damping: float = 0.06     # pulls GV down each step (self-healing)
    floor: float = 0.0        # GV lower bound
    ceiling: float = 100.0    # GV upper bound

    # Strain weights
    w_tokens: float = 0.002
    w_tool_calls: float = 1.25
    w_errors: float = 3.0
    w_repeat: float = 0.9
    w_recursion: float = 0.6

    # Thresholds
    yellow_at: float = 35.0
    red_at: float = 70.0


@dataclass
class GuardState:
    gv: float = 0.0
    step: int = 0


class GVRuntimeGuard:
    """
    Deterministic runtime risk signal.

    Update:
      GV(t+1) = clamp( GV(t) + strain - damping*GV(t) )

    Output:
      - gv: current score
      - band: green/yellow/red
      - recommended_action: continue/slow/halt
    """

    def __init__(self, config: GuardConfig | None = None):
        self.config = config or GuardConfig()
        self.state = GuardState()

    def reset(self) -> None:
        self.state = GuardState()

    def compute_strain(self, s: RuntimeSignals) -> float:
        s = s.clamp_nonnegative()
        c = self.config

        strain = 0.0
        strain += c.w_tokens * float(s.token_delta)
        strain += c.w_tool_calls * float(s.tool_calls_delta)
        strain += c.w_errors * float(s.error_delta)
        strain += c.w_repeat * float(s.repeated_action_delta)
        strain += c.w_recursion * float(s.recursion_depth)

        # Optional mild latency penalty (often correlates with thrash)
        if s.latency_ms is not None and s.latency_ms > 1500:
            strain += 0.5

        return strain

    def step(self, signals: RuntimeSignals) -> Dict[str, Any]:
        c = self.config
        strain = self.compute_strain(signals)

        gv_prev = self.state.gv
        gv_next = gv_prev + strain - (c.damping * gv_prev)

        # Clamp
        gv_next = max(c.floor, min(c.ceiling, gv_next))

        self.state.gv = gv_next
        self.state.step += 1

        if gv_next >= c.red_at:
            band: RiskBand = "red"
            action: Action = "halt"
        elif gv_next >= c.yellow_at:
            band = "yellow"
            action = "slow"
        else:
            band = "green"
            action = "continue"

        return {
            "step": self.state.step,
            "gv": round(gv_next, 4),
            "strain": round(strain, 4),
            "band": band,
            "recommended_action": action,
            "signals": asdict(signals),
        }
