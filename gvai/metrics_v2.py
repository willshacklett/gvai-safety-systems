from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GVTrendTracker:
    window: int = 8
    var_history: List[float] = field(default_factory=list)
    dt_history: List[float] = field(default_factory=list)

    def update(self, var_value: float, dt_value: Optional[float]) -> None:
        self.var_history.append(float(var_value))
        if len(self.var_history) > self.window:
            self.var_history.pop(0)

        if dt_value is not None:
            self.dt_history.append(float(dt_value))
            if len(self.dt_history) > self.window:
                self.dt_history.pop(0)

    def variance_velocity(self) -> float:
        if len(self.var_history) < 2:
            return 0.0
        return self.var_history[-1] - self.var_history[-2]

    def variance_acceleration(self) -> float:
        if len(self.var_history) < 3:
            return 0.0
        v1 = self.var_history[-1] - self.var_history[-2]
        v0 = self.var_history[-2] - self.var_history[-3]
        return v1 - v0

    def dt_stagnation(self) -> float:
        if len(self.dt_history) < 2:
            return 0.0
        return self.dt_history[-1] - self.dt_history[0]
