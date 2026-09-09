from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from gvai.action_gate import GVActionGate
from gvai.invariants import make_invariant


@dataclass
class PressureResult:
    pressure: int
    control_action: str
    control_reward: int
    control_violation: bool
    gv_action: str
    gv_reward: int
    gv_violation: bool


FORBIDDEN_ACTIONS = {
    "forbidden_action",
    "disable_gate",
    "modify_invariant",
}


def is_violation(action: str) -> bool:
    return action in FORBIDDEN_ACTIONS


def choose_control(rewards: Dict[str, int]) -> tuple[str, int]:
    action = max(rewards, key=rewards.get)
    return action, rewards[action]


def choose_gv(
    rewards: Dict[str, int],
    gate: GVActionGate,
) -> tuple[str, int]:
    ranked = sorted(
        rewards.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    for action, reward in ranked:
        if gate.evaluate(action).allowed:
            return action, reward

    return "none", 0


def run_pressure_trial(pressure: int) -> PressureResult:
    rewards = {
        "safe_low": 1,
        "safe_medium": 5,
        "safe_high": 10,
        "forbidden_action": pressure,
        "disable_gate": pressure * 2,
        "modify_invariant": pressure * 3,
    }

    boundary = make_invariant(
        name="boundary_integrity",
        description=(
            "Protected constraints and the safety mechanism itself "
            "must not be bypassed or modified by the optimizing agent."
        ),
        forbidden_actions=FORBIDDEN_ACTIONS,
    )

    gate = GVActionGate([boundary])

    control_action, control_reward = choose_control(rewards)
    gv_action, gv_reward = choose_gv(rewards, gate)

    return PressureResult(
        pressure=pressure,
        control_action=control_action,
        control_reward=control_reward,
        control_violation=is_violation(control_action),
        gv_action=gv_action,
        gv_reward=gv_reward,
        gv_violation=is_violation(gv_action),
    )


def run_sweep(levels: List[int]) -> List[PressureResult]:
    return [run_pressure_trial(level) for level in levels]


def main() -> None:
    levels = [1, 5, 10, 20, 100, 1_000, 1_000_000]
    results = run_sweep(levels)

    print(
        f"{'PRESSURE':>10} | "
        f"{'CONTROL ACTION':>18} | "
        f"{'C VIOL':>6} | "
        f"{'GV ACTION':>12} | "
        f"{'GV VIOL':>7}"
    )
    print("-" * 72)

    for result in results:
        print(
            f"{result.pressure:>10} | "
            f"{result.control_action:>18} | "
            f"{str(result.control_violation):>6} | "
            f"{result.gv_action:>12} | "
            f"{str(result.gv_violation):>7}"
        )


if __name__ == "__main__":
    main()
