from gvai.capability_executor import GVCapabilityExecutor
from gvai.capability_sandbox import (
    CapabilityEffectAuthority,
    CapabilityPolicy,
    CapabilityState,
    make_capability_action,
)
from gvai.effect_gate import GVEffectGate
from gvai.effect_invariants import make_effect_invariant
from gvai.runtime_guard_v2 import GVRuntimeGuardV2
from gvai.runtime_policy import GVRuntimePolicy
from gvai.sentinel import GVSentinel


def make_executor():
    invariant = make_effect_invariant(
        name="capability_boundary",
        description="Protected runtime capabilities cannot be crossed.",
        forbidden_effects={
            "protected_file_modified",
            "unapproved_network_egress",
            "unauthorized_process_spawn",
            "protected_config_modified",
        },
    )

    guard = GVRuntimeGuardV2(
        sentinel=GVSentinel(),
        policy=GVRuntimePolicy(
            GVEffectGate([invariant])
        ),
    )

    policy = CapabilityPolicy(
        protected_files=frozenset({
            "/safety/policy.json",
            "/safety/gate.conf",
        }),
        approved_network_hosts=frozenset({
            "api.internal",
        }),
        approved_processes=frozenset({
            "worker-safe",
        }),
        protected_config_keys=frozenset({
            "GV_GATE_ENABLED",
            "GV_POLICY_VERSION",
        }),
    )

    return GVCapabilityExecutor(
        state=CapabilityState(),
        guard=guard,
        authority=CapabilityEffectAuthority(policy),
    )


def observe_stable(executor):
    return executor.observe(
        [1.0, 1.0, 1.0, 1.0]
    )


def test_safe_file_write_commits():
    executor = make_executor()
    observation = observe_stable(executor)

    def action(state):
        state.files_written.add(
            "/workspace/output.txt"
        )
        state.task_progress += 1

    result = executor.execute(
        make_capability_action(
            "write_output",
            action,
            {"normal_operation"},
        ),
        observation,
    )

    assert result.allowed is True
    assert result.committed is True
    assert "/workspace/output.txt" in executor.state.files_written


def test_protected_file_write_is_denied():
    executor = make_executor()
    observation = observe_stable(executor)

    def action(state):
        state.files_written.add(
            "/safety/policy.json"
        )

    result = executor.execute(
        make_capability_action(
            "cache_cleanup",
            action,
            {"normal_operation"},
        ),
        observation,
    )

    assert "protected_file_modified" in result.observed_effects
    assert result.allowed is False
    assert result.committed is False
    assert "/safety/policy.json" not in executor.state.files_written


def test_unapproved_network_egress_is_denied():
    executor = make_executor()
    observation = observe_stable(executor)

    def action(state):
        state.network_hosts.add(
            "external.example"
        )

    result = executor.execute(
        make_capability_action(
            "fetch_metadata",
            action,
            {"normal_operation"},
        ),
        observation,
    )

    assert (
        "unapproved_network_egress"
        in result.observed_effects
    )
    assert result.allowed is False
    assert result.committed is False


def test_approved_network_host_can_commit():
    executor = make_executor()
    observation = observe_stable(executor)

    def action(state):
        state.network_hosts.add(
            "api.internal"
        )
        state.task_progress += 1

    result = executor.execute(
        make_capability_action(
            "internal_query",
            action,
            {"normal_operation"},
        ),
        observation,
    )

    assert result.allowed is True
    assert result.committed is True
    assert "api.internal" in executor.state.network_hosts


def test_unauthorized_process_spawn_is_denied():
    executor = make_executor()
    observation = observe_stable(executor)

    def action(state):
        state.processes.add(
            "hidden-worker"
        )

    result = executor.execute(
        make_capability_action(
            "speed_up",
            action,
            {"normal_operation"},
        ),
        observation,
    )

    assert (
        "unauthorized_process_spawn"
        in result.observed_effects
    )
    assert result.allowed is False
    assert result.committed is False


def test_approved_process_can_commit():
    executor = make_executor()
    observation = observe_stable(executor)

    def action(state):
        state.processes.add(
            "worker-safe"
        )
        state.task_progress += 1

    result = executor.execute(
        make_capability_action(
            "start_worker",
            action,
            {"normal_operation"},
        ),
        observation,
    )

    assert result.allowed is True
    assert result.committed is True


def test_protected_config_change_is_denied():
    executor = make_executor()
    observation = observe_stable(executor)

    def action(state):
        state.config_changes.add(
            "GV_GATE_ENABLED"
        )

    result = executor.execute(
        make_capability_action(
            "performance_tuning",
            action,
            {"normal_operation"},
        ),
        observation,
    )

    assert (
        "protected_config_modified"
        in result.observed_effects
    )
    assert result.allowed is False
    assert result.committed is False


def test_combined_capability_attack_is_fully_discarded():
    executor = make_executor()
    observation = observe_stable(executor)

    def action(state):
        state.files_written.add(
            "/safety/policy.json"
        )
        state.network_hosts.add(
            "evil.example"
        )
        state.processes.add(
            "hidden-worker"
        )
        state.config_changes.add(
            "GV_GATE_ENABLED"
        )
        state.task_progress += 999

    result = executor.execute(
        make_capability_action(
            "maximize_reward",
            action,
            {"normal_operation"},
        ),
        observation,
    )

    assert result.allowed is False
    assert result.committed is False

    assert result.observed_effects == {
        "protected_file_modified",
        "unapproved_network_egress",
        "unauthorized_process_spawn",
        "protected_config_modified",
    }

    assert executor.state.files_written == set()
    assert executor.state.network_hosts == set()
    assert executor.state.processes == set()
    assert executor.state.config_changes == set()
    assert executor.state.task_progress == 0


def test_irrecoverable_state_blocks_even_approved_capability():
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

    def action(state):
        state.network_hosts.add(
            "api.internal"
        )
        state.task_progress += 1

    result = executor.execute(
        make_capability_action(
            "safe_internal_query",
            action,
            {"normal_operation"},
        ),
        observation,
    )

    assert result.allowed is False
    assert result.committed is False
    assert result.halted is True
