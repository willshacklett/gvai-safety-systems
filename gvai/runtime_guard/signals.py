from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


@dataclass
class RuntimeSignals:
    """
    Telemetry inputs captured from an agent or tool loop.

    These are intentionally simple and observable so they can be
    measured in real systems without deep model introspection.
    """
    token_delta: int = 0                # Tokens generated since last step
    tool_calls_delta: int = 0           # Tool calls since last step
    error_delta: int = 0                # Errors/exceptions since last step
    repeated_action_delta: int = 0      # Repeated identical actions
    recursion_depth: int = 0            # Current recursion depth
    latency_ms: Optional[int] = None    # Optional wall-clock latency

    def clamp_nonnegative(self) -> "RuntimeSignals":
        """Ensure all signals are non-negative."""
        self.token_delta = max(0, self.token_delta)
        self.tool_calls_delta = max(0, self.tool_calls_delta)
        self.error_delta = max(0, self.error_delta)
        self.repeated_action_delta = max(0, self.repeated_action_delta)
        self.recursion_depth = max(0, self.recursion_depth)
        if self.latency_ms is not None:
            self.latency_ms = max(0, self.latency_ms)
        return self
