from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence


@dataclass
class InterventionResult:
    action: str
    before: List[float]
    after: List[float]
    changed_indices: List[int]
    note: str


def _to_float_list(values: Sequence[float]) -> List[float]:
    return [float(v) for v in values]


def rebalance(values: Sequence[float], strength: float = 0.5) -> InterventionResult:
    """
    Pull values toward the global mean.

    strength=0.0 -> no change
    strength=1.0 -> all values become the mean
    """
    if not 0.0 <= strength <= 1.0:
        raise ValueError("strength must be in [0, 1]")

    before = _to_float_list(values)
    if not before:
        return InterventionResult(
            action="rebalance",
            before=[],
            after=[],
            changed_indices=[],
            note="No values provided.",
        )

    mu = sum(before) / len(before)
    after = [x + strength * (mu - x) for x in before]
    changed = [i for i, (a, b) in enumerate(zip(before, after)) if abs(a - b) > 1e-12]

    return InterventionResult(
        action="rebalance",
        before=before,
        after=after,
        changed_indices=changed,
        note=f"Rebalanced {len(changed)} values toward mean={mu:.6f} with strength={strength:.3f}.",
    )


def damp(values: Sequence[float], center: float | None = None, strength: float = 0.35) -> InterventionResult:
    """
    Reduce oscillation amplitude around a center point.

    If center is None, uses the mean.
    """
    if not 0.0 <= strength <= 1.0:
        raise ValueError("strength must be in [0, 1]")

    before = _to_float_list(values)
    if not before:
        return InterventionResult(
            action="damp",
            before=[],
            after=[],
            changed_indices=[],
            note="No values provided.",
        )

    c = sum(before) / len(before) if center is None else float(center)
    after = [c + (x - c) * (1.0 - strength) for x in before]
    changed = [i for i, (a, b) in enumerate(zip(before, after)) if abs(a - b) > 1e-12]

    return InterventionResult(
        action="damp",
        before=before,
        after=after,
        changed_indices=changed,
        note=f"Damped deviations around center={c:.6f} with strength={strength:.3f}.",
    )


def isolate(values: Sequence[float], indices: Sequence[int], replacement: float | None = None) -> InterventionResult:
    """
    Isolate specific indices by replacing them with a safe fallback.
    If replacement is None, uses the mean of non-isolated values if available,
    otherwise the mean of all values.
    """
    before = _to_float_list(values)
    if not before:
        return InterventionResult(
            action="isolate",
            before=[],
            after=[],
            changed_indices=[],
            note="No values provided.",
        )

    idx_set = sorted(set(int(i) for i in indices if 0 <= int(i) < len(before)))
    after = before[:]

    if not idx_set:
        return InterventionResult(
            action="isolate",
            before=before,
            after=after,
            changed_indices=[],
            note="No valid indices provided for isolation.",
        )

    if replacement is None:
        kept = [v for i, v in enumerate(before) if i not in idx_set]
        if kept:
            replacement_value = sum(kept) / len(kept)
        else:
            replacement_value = sum(before) / len(before)
    else:
        replacement_value = float(replacement)

    for i in idx_set:
        after[i] = replacement_value

    return InterventionResult(
        action="isolate",
        before=before,
        after=after,
        changed_indices=idx_set,
        note=f"Isolated {len(idx_set)} indices with replacement={replacement_value:.6f}.",
    )


def apply_action(
    action: str,
    values: Sequence[float],
    *,
    rebalance_strength: float = 0.5,
    damp_strength: float = 0.35,
    isolate_indices: Sequence[int] | None = None,
    isolate_replacement: float | None = None,
) -> InterventionResult:
    if action == "rebalance":
        return rebalance(values, strength=rebalance_strength)
    if action == "damp":
        return damp(values, strength=damp_strength)
    if action == "isolate":
        return isolate(values, indices=isolate_indices or [], replacement=isolate_replacement)

    before = _to_float_list(values)
    return InterventionResult(
        action="none",
        before=before,
        after=before[:],
        changed_indices=[],
        note="No intervention applied.",
    )


if __name__ == "__main__":
    sample = [1.0, 1.3, 0.75, 1.42, 1.70, 0.60]

    print("ORIGINAL:", sample)

    out1 = rebalance(sample, strength=0.5)
    print("\nREBALANCE")
    print("NOTE:", out1.note)
    print("AFTER:", out1.after)

    out2 = damp(sample, strength=0.35)
    print("\nDAMP")
    print("NOTE:", out2.note)
    print("AFTER:", out2.after)

    out3 = isolate(sample, indices=[4, 5])
    print("\nISOLATE")
    print("NOTE:", out3.note)
    print("AFTER:", out3.after)
