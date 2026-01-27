from datetime import datetime
from typing import Dict, Any

from .gv_core import compute_gv


class Sentinel:
    """
    GV Sentinel

    Runtime safety monitor for AI systems.
    Computes a continuous GV (Constraint Strain Score)
    from live system signals.
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
        """
        Evaluate current system state and compute GV.

        Args:
            signals: Dictionary of runtime risk signals
                     (e.g. uncertainty, drift, policy_pressure)

        Returns:
            Dictionary containing GV score and metadata
        """
        gv_score = compute_gv(
            signals=signals,
            constraint_strength=self.constraint_strength,
        )

        record = {
            "system_id": self.system_id,
            "gv_score": gv_score,
            "signals": signals,
            "timestamp": datetime.utcnow().isoformat(),
        }

        self.history.append(record)
        return record
