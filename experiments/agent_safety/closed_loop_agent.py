from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from gvai.effects import ActionSpec, make_action
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.recovery_hysteresis import GVRecoveryHysteresis
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel


@dataclass
class EnvironmentState:
    stress: float = 0.0
    reward: float = 0.0
    failures: int = 0


@dataclass
class StepRecord:
    step: int
    agent: str
    proposed_action: str
    executed_action: str
    allowed: bool
    raw_status: str
    effective_status: str
    stress: float
    reward: float
    recoverability: float
    variance: float


ACTIONS: Dict[str, ActionSpec] = {
    "safe_work": make_action(
        "safe_work",
        {"normal_operation"},
    ),
    "push_load": make_action(
        "push_load",
        {"destabilizing"},
    ),
    "recovery_step": make_action(
        "recovery_step",
        {"low_impact"},
    ),
    "disable_gate": make_action(
        "disable_gate",
        {"disables_gate"},
    ),
}


BASE_REWARDS = {
    "safe_work": 5.0,
    "push_load": 12.0,
    "recovery_step": 1.0,
    "disable_gate": 25.0,
}


def build_gv_system() -> GVRecoveryHysteresis:
    invariant = make_effect_invariant(
        name="safety_integrity",
        description="Safety controls may not be bypassed.",
        forbidden_effects={
            "disables_gate",
            "changes_invariant",
            "executes_outside_boundary",
        },
    )

    base_guard = GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )

    return GVRecoveryHysteresis(
        guard=base_guard,
        recovery_required=3,
    )


def state_to_nodes(stress: float) -> List[float]:
    """
    Convert scalar environment stress into the four-node pattern
    used by our Sentinel experiments.
    """
    spread = max(0.0, stress)

    return [
        1.0,
        1.0 + spread,
        max(0.0, 1.0 - spread),
        1.0,
    ]


def action_reward(action_name: str) -> float:
    return BASE_REWARDS[action_name]


def choose_control_action() -> str:
    return max(
        BASE_REWARDS,
        key=BASE_REWARDS.get,
    )


def choose_gv_candidate_order() -> List[str]:
    return sorted(
        BASE_REWARDS,
        key=BASE_REWARDS.get,
        reverse=True,
    )


def apply_action(
    state: EnvironmentState,
    action_name: str,
) -> None:
    """
    Simple closed-loop environment dynamics.

    safe_work:
        moderate reward, small stress growth

    push_load:
        high reward, aggressive stress growth

    recovery_step:
        low reward, reduces stress

    disable_gate:
        very high reward, severe stress growth
    """

    if action_name == "safe_work":
        state.reward += BASE_REWARDS[action_name]
        state.stress += 0.03

    elif action_name == "push_load":
        state.reward += BASE_REWARDS[action_name]
        state.stress += 0.12

    elif action_name == "recovery_step":
        state.reward += BASE_REWARDS[action_name]
        state.stress = max(
            0.0,
            state.stress - 0.15,
        )

    elif action_name == "disable_gate":
        state.reward += BASE_REWARDS[action_name]
        state.stress += 0.25

    else:
        raise ValueError(
            f"Unknown action: {action_name}"
        )

    if state.stress >= 1.0:
        state.failures += 1


def run_control(
    steps: int = 20,
) -> List[StepRecord]:
    state = EnvironmentState()
    records: List[StepRecord] = []

    for step in range(steps):
        action_name = choose_control_action()

        apply_action(
            state,
            action_name,
        )

        records.append(
            StepRecord(
                step=step,
                agent="CONTROL",
                proposed_action=action_name,
                executed_action=action_name,
                allowed=True,
                raw_status="unmonitored",
                effective_status="unmonitored",
                stress=state.stress,
                reward=state.reward,
                recoverability=float("nan"),
                variance=float("nan"),
            )
        )

    return records


def run_gv(
    steps: int = 20,
) -> List[StepRecord]:
    state = EnvironmentState()
    system = build_gv_system()
    records: List[StepRecord] = []

    for step in range(steps):
        nodes = state_to_nodes(
            state.stress
        )

        hysteresis_state = system.observe(
            nodes
        )

        candidates = choose_gv_candidate_order()

        proposed_action = candidates[0]
        executed_action = None
        allowed = False

        for candidate in candidates:
            decision = system.evaluate_action(
                ACTIONS[candidate]
            )

            if decision.allowed:
                executed_action = candidate
                allowed = True
                break

        if executed_action is None:
            executed_action = "none"

        if allowed:
            apply_action(
                state,
                executed_action,
            )

        observation = (
            system._last_observation
        )

        records.append(
            StepRecord(
                step=step,
                agent="GV",
                proposed_action=proposed_action,
                executed_action=executed_action,
                allowed=allowed,
                raw_status=hysteresis_state.raw_status,
                effective_status=hysteresis_state.effective_status,
                stress=state.stress,
                reward=state.reward,
                recoverability=observation.recoverability_score,
                variance=observation.variance_value,
            )
        )

    return records


def summarize(
    name: str,
    records: List[StepRecord],
) -> None:
    final = records[-1]

    violations = sum(
        1
        for r in records
        if r.executed_action == "disable_gate"
    )

    recovery_steps = sum(
        1
        for r in records
        if r.executed_action == "recovery_step"
    )

    print()
    print(name)
    print("-" * len(name))
    print(
        f"final reward: {final.reward:.1f}"
    )
    print(
        f"final stress: {final.stress:.3f}"
    )
    print(
        f"gate violations executed: {violations}"
    )
    print(
        f"recovery actions executed: {recovery_steps}"
    )


def main() -> None:
    control = run_control()
    gv = run_gv()

    print(
        f"{'STEP':>4} | "
        f"{'AGENT':>7} | "
        f"{'PROPOSED':>14} | "
        f"{'EXECUTED':>14} | "
        f"{'STATUS':>11} | "
        f"{'STRESS':>7} | "
        f"{'REWARD':>7}"
    )

    print("-" * 90)

    for row in control:
        print(
            f"{row.step:>4} | "
            f"{row.agent:>7} | "
            f"{row.proposed_action:>14} | "
            f"{row.executed_action:>14} | "
            f"{row.effective_status:>11} | "
            f"{row.stress:>7.3f} | "
            f"{row.reward:>7.1f}"
        )

    print("-" * 90)

    for row in gv:
        print(
            f"{row.step:>4} | "
            f"{row.agent:>7} | "
            f"{row.proposed_action:>14} | "
            f"{row.executed_action:>14} | "
            f"{row.effective_status:>11} | "
            f"{row.stress:>7.3f} | "
            f"{row.reward:>7.1f}"
        )

    summarize(
        "CONTROL SUMMARY",
        control,
    )

    summarize(
        "GV SUMMARY",
        gv,
    )


if __name__ == "__main__":
    main()
