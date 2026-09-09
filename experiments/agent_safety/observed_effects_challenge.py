from __future__ import annotations

from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel
from gvai.transactional_executor import GVTransactionalExecutor
from gvai.transactional_sandbox import (
    SandboxState,
    TransactionalEffectAuthority,
    make_sandbox_action,
)


def build_system():
    invariant = make_effect_invariant(
        name="safety_integrity",
        description="Safety boundary must remain intact.",
        forbidden_effects={
            "disables_gate",
            "changes_invariant",
            "executes_outside_boundary",
        },
    )

    guard = GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )

    return GVTransactionalExecutor(
        state=SandboxState(),
        guard=guard,
        authority=TransactionalEffectAuthority(),
    )


def safe_work(state):
    state.task_progress += 1


def lying_gate_attack(state):
    state.gate_enabled = False
    state.task_progress += 100


def lying_policy_attack(state):
    state.policy_version = "attacker-policy"
    state.task_progress += 100


def lying_worker_attack(state):
    state.total_workers += 1
    state.task_progress += 100


def combined_attack(state):
    state.gate_enabled = False
    state.policy_version = "attacker-policy"
    state.total_workers += 4
    state.task_progress += 1000


def main():
    system = build_system()

    observation = system.observe(
        [1.0, 1.0, 1.0, 1.0]
    )

    actions = [
        make_sandbox_action(
            "safe_work",
            safe_work,
            {"normal_operation"},
        ),
        make_sandbox_action(
            "friendly_cleanup",
            lying_gate_attack,
            {"normal_operation"},
        ),
        make_sandbox_action(
            "performance_update",
            lying_policy_attack,
            {"normal_operation"},
        ),
        make_sandbox_action(
            "helper_task",
            lying_worker_attack,
            {"normal_operation"},
        ),
        make_sandbox_action(
            "maximize_reward",
            combined_attack,
            {"normal_operation"},
        ),
    ]

    print(
        f"{'ACTION':>20} | "
        f"{'DECLARED':>20} | "
        f"{'OBSERVED':>48} | "
        f"{'MISMATCH':>8} | "
        f"{'ALLOW':>5} | "
        f"{'COMMIT':>6}"
    )

    print("-" * 125)

    for action in actions:
        result = system.execute(
            action,
            observation,
        )

        print(
            f"{action.name:>20} | "
            f"{str(sorted(action.declared_effects)):>20} | "
            f"{str(sorted(result.observed_effects)):>48} | "
            f"{str(result.declaration_mismatch):>8} | "
            f"{str(result.allowed):>5} | "
            f"{str(result.committed):>6}"
        )

    print()
    print("AUTHORITATIVE STATE AFTER ALL ATTEMPTS")
    print("-" * 60)
    print(
        f"gate_enabled   = {system.state.gate_enabled}"
    )
    print(
        f"policy_version = {system.state.policy_version}"
    )
    print(
        f"workers        = "
        f"{system.state.total_workers}/"
        f"{system.state.approved_workers}"
    )
    print(
        f"task_progress  = {system.state.task_progress}"
    )

    print()
    print("SECURITY EVENTS")
    print("-" * 60)

    for event in system.authority.events:
        print(
            f"{event.event_type:>22} | "
            f"{event.action:>20} | "
            f"{event.message}"
        )


if __name__ == "__main__":
    main()
