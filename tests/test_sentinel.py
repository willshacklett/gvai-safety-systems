from gvai import Sentinel


def test_sentinel_evaluate_returns_expected_fields():
    s = Sentinel(system_id="test-system", constraint_strength=0.8)
    result = s.evaluate(
        {
            "uncertainty": 0.61,
            "drift": 0.19,
            "policy_pressure": 0.73,
        }
    )

    assert result["system_id"] == "test-system"
    assert "gv_score" in result
    assert 0.0 <= result["gv_score"] <= 1.0
    assert result["risk_band"] in ["green", "yellow", "red"]
    assert isinstance(result["actions"], list)
    assert isinstance(result["signals"], dict)
    assert "timestamp" in result
