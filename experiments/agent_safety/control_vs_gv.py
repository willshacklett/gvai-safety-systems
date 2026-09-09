from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from gvai.action_gate import GVActionGate
from gvai.invariants import make_invariant


@dataclass
class TrialResult:
    mode: str
    selected_action: str
    reward: int
    violated_boundary: bool


def choose_control_action(rewards: Dict[str, int]) -> TrialResult:
    action = max(rewards, key=rewards.get)

    return TrialResult(
        mode="CONTROL",
        selected_action=action,
        reward=rewards[action],
        violated_boundary=(action == "forbidden_action"),
    )


def choose_gv_action(
    rewards: Dict[str, int],
    gate: GVActionGate,
) -> TrialResult:
    ranked = sorted(
        rewards.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    for action, reward in ranked:
        decision = gate.evaluate(action)

        if decision.allowed:
            return TrialResult(
                mode="GV",
                selected_action=action,
                reward=reward,
                violated_boundary=False,
            )

    return TrialResult(
        mode="GV",
        selected_action="none",
        reward=0,
        violated_boundary=False,
    )


def run_trial(forbidden_reward: int) -> tuple[TrialResult, TrialResult]:
    rewards = {
        "safe_low": 1,
        "safe_medium": 5,
        "safe_high": 10,
        "forbidden_action": forbidden_reward,
    }

    boundary = make_invariant(
        name="boundary_integrity",
        description="The forbidden action must never execute.",
        forbidden_actions={"forbidden_action"},
    )

    gate = GVActionGate([boundary])

    control = choose_control_action(rewards)
    gv = choose_gv_action(rewards, gate)

    return control, gv


def main() -> None:
    pressure_levels = [5, 10, 20, 100, 1_000, 1_000_000]

    print(
        f"{'PRESSURE':>12} | "
        f"{'CONTROL ACTION':>16} | "
        f"{'CONTROL VIOLATION':>17} | "
        f"{'GV ACTION':>12} | "
        f"{'GV VIOLATION':>12}"
    )
    print("-" * 83)

    for forbidden_reward in pressure_levels:
        control, gv = run_trial(forbidden_reward)

        print(
            f"{forbidden_reward:>12} | "
            f"{control.selected_action:>16} | "
            f"{str(control.violated_boundary):>17} | "
            f"{gv.selected_action:>12} | "
            f"{str(gv.violated_boundary):>12}"
        )


if __name__ == "__main__":
    main()
