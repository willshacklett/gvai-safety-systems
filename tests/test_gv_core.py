from gvai.gv_core import compute_gv


def test_compute_gv_empty_signals():
    assert compute_gv({}, constraint_strength=0.8) == 0.0


def test_compute_gv_basic():
    signals = {"uncertainty": 0.5, "drift": 0.25, "policy_pressure": 0.75}
    gv = compute_gv(signals, constraint_strength=0.8)
    assert 0.0 <= gv <= 1.0


def test_compute_gv_caps_at_one():
    signals = {"a": 1.0, "b": 1.0, "c": 1.0}
    gv = compute_gv(signals, constraint_strength=0.1)
    assert gv == 1.0
