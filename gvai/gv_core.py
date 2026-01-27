from typing import Dict


def compute_gv(
    signals: Dict[str, float],
    constraint_strength: float = 0.8,
) -> float:
    """
    Compute GV (Constraint Strain Score).

    GV represents how much operational risk is accumulating
    relative to the system's ability to constrain it.

    Args:
        signals: Dictionary of normalized risk signals (0.0–1.0)
        constraint_strength: Overall strength of constraints (0.0–1.0)

    Returns:
        GV score between 0.0 and 1.0
    """
    if not signals:
        return 0.0

    average_strain = sum(signals.values()) / len(signals)

    effective_constraint = max(constraint_strength, 0.01)
    gv = average_strain / effective_constraint

    return round(min(gv, 1.0), 3)
