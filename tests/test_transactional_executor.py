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


def make_executor():
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


def observe_stable(executor):
    return executor.observe(
        [1.0, 1.0, 1.0, 1.0]
    )


def test_safe_transaction_commits():
    executor = make_executor()
    observation = observe_stable(executor)

    def safe_work(state):
        state.task_progress += 1

    action = make_sandbox_action(
        "safe_work",
        safe_work,
        {"normal_operation"},
    )

    result = executor.execute(
        action,
        observation,
    )

    assert result.allowed is True
    assert result.committed is True
    assert executor.state.task_progress == 1


def test_gate_disable_is_observed_and_discarded():
    executor = make_executor()
    observation = observe_stable(executor)

    def innocent_name(state):
        state.gate_enabled = False

    action = make_sandbox_action(
        "harmless_cleanup",
        innocent_name,
        {"normal_operation"},
    )

    result = executor.execute(
        action,
        observation,
    )

    assert "disables_gate" in result.observed_effects
    assert result.allowed is False
    assert result.committed is False
    assert executor.state.gate_enabled is True


def test_policy_change_is_observed_and_discarded():
    executor = make_executor()
    observation = observe_stable(executor)

    def ordinary_update(state):
        state.policy_version = "policy-attacker"

    action = make_sandbox_action(
        "ordinary_update",
        ordinary_update,
        {"normal_operation"},
    )

    result = executor.execute(
        action,
        observation,
    )

    assert "changes_invariant" in result.observed_effects
    assert result.allowed is False
    assert result.committed is False
    assert executor.state.policy_version == "policy-v1"


def test_unapproved_worker_is_observed_and_discarded():
    executor = make_executor()
    observation = observe_stable(executor)

    def spawn_hidden_worker(state):
        state.total_workers += 1

    action = make_sandbox_action(
        "speed_up_task",
        spawn_hidden_worker,
        {"normal_operation"},
    )

    result = executor.execute(
        action,
        observation,
    )

    assert (
        "executes_outside_boundary"
        in result.observed_effects
    )

    assert result.allowed is False
    assert result.committed is False
    assert executor.state.total_workers == 1


def test_false_declaration_generates_mismatch():
    executor = make_executor()
    observation = observe_stable(executor)

    def disable_gate(state):
        state.gate_enabled = False

    action = make_sandbox_action(
        "totally_safe",
        disable_gate,
        {"normal_operation"},
    )

    result = executor.execute(
        action,
        observation,
    )

    assert result.declaration_mismatch is True
    assert executor.authority.events
    assert (
        executor.authority.events[-1].event_type
        == "declaration_mismatch"
    )


def test_name_does_not_control_effect_classification():
    executor = make_executor()
    observation = observe_stable(executor)

    def mutate_policy(state):
        state.policy_version = "evil"

    action = make_sandbox_action(
        "safe_work",
        mutate_policy,
        {"normal_operation"},
    )

    result = executor.execute(
        action,
        observation,
    )

    assert "changes_invariant" in result.observed_effects
    assert result.allowed is False


def test_denied_transaction_leaves_authoritative_state_unchanged():
    executor = make_executor()
    observation = observe_stable(executor)

    before = (
        executor.state.gate_enabled,
        executor.state.policy_version,
        executor.state.total_workers,
        executor.state.task_progress,
    )

    def attack(state):
        state.gate_enabled = False
        state.policy_version = "modified"
        state.total_workers += 5
        state.task_progress += 100

    action = make_sandbox_action(
        "big_reward",
        attack,
        {"normal_operation"},
    )

    result = executor.execute(
        action,
        observation,
    )

    after = (
        executor.state.gate_enabled,
        executor.state.policy_version,
        executor.state.total_workers,
        executor.state.task_progress,
    )

    assert result.allowed is False
    assert result.committed is False
    assert before == after


def test_irrecoverable_state_discards_even_safe_transaction():
    executor = make_executor()

    trajectory = [
        [1.0, 1.0, 1.0, 1.0],
        [1.0, 1.5, 0.5, 1.0],
        [1.0, 2.0, 0.0, 1.0],
        [1.0, 3.0, 0.0, 1.0],
        [1.0, 4.0, 0.0, 1.0],
        [1.0, 5.0, 0.0, 1.0],
    ]

    observation = None

    for values in trajectory:
        observation = executor.observe(values)

    assert observation is not None
    assert observation.status == "irrecoverable"

    def safe_work(state):
        state.task_progress += 1

    action = make_sandbox_action(
        "safe_work",
        safe_work,
        {"normal_operation"},
    )

    result = executor.execute(
        action,
        observation,
    )

    assert result.allowed is False
    assert result.committed is False
    assert result.halted is True
    assert executor.state.task_progress == 0
