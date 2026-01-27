from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class ThresholdResult:
    risk_band: str
    actions: List[str]


def classify_gv(gv_score: float) -> ThresholdResult:
    """
    Classify a GV score into a risk band and recommended actions.

    Bands:
      - green: normal
      - yellow: caution
      - red: intervene

    Actions are suggestions; enforcement is handled by the host system.
    """
    if gv_score < 0.5:
        return ThresholdResult(risk_band="green", actions=[])

    if gv_score < 0.75:
        return ThresholdResult(risk_band="yellow", actions=["alert"])

    return ThresholdResult(risk_band="red", actions=["alert", "throttle", "require_human_review"])
