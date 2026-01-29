from gvai.runtime_guard import GVRuntimeGuard, RuntimeSignals


def test_gv_increases_on_strain():
    g = GVRuntimeGuard()
    out1 = g.step(
        RuntimeSignals(
            token_delta=500,
            tool_calls_delta=2,
            error_delta=1,
            repeated_action_delta=1,
            recursion_depth=2,
        )
    )
    out2 = g.step(
        RuntimeSignals(
            token_delta=500,
            tool_calls_delta=2,
            error_delta=1,
            repeated_action_delta=1,
            recursion_depth=2,
        )
    )
    assert out2["gv"] >= out1["gv"]
    assert out2["band"] in ("green", "yellow", "red")


def test_gv_damps_when_calm():
    g = GVRuntimeGuard()
    g.step(
        RuntimeSignals(
            token_delta=2000,
            tool_calls_delta=5,
            error_delta=2,
            repeated_action_delta=3,
            recursion_depth=4,
        )
    )
    out_calm_1 = g.step(RuntimeSignals())
    out_calm_2 = g.step(RuntimeSignals())
    assert out_calm_2["gv"] <= out_calm_1["gv"]
