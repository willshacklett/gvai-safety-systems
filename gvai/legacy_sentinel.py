from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from .gv_core import compute_gv
from .thresholds import classify_gv


class Sentinel:
    """
    Legacy GV Sentinel compatibility API.

    Computes a continuous GV Constraint Strain Score from runtime
    signals, then classifies that score into the historical
    green / yellow / red risk bands.

    This class is preserved for backward compatibility.
    New recoverability-aware code should use GVSentinel.
    """

    def __init__(
        self,
        system_id: str,
        constraint_strength: float = 0.8,
    ):
        self.system_id = system_id
        self.constraint_strength = constraint_strength
        self.history = []

    def evaluate(self, signals: Dict[str, float]) -> Dict[str, Any]:
        gv_score = compute_gv(
            signals=signals,
            constraint_strength=self.constraint_strength,
        )

        threshold = classify_gv(gv_score)

        record = {
            "system_id": self.system_id,
            "gv_score": gv_score,
            "risk_band": threshold.risk_band,
            "actions": list(threshold.actions),
            "signals": dict(signals),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        self.history.append(record)
        return record
