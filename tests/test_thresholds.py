from gvai.thresholds import classify_gv


def test_green_band():
    result = classify_gv(0.2)
    assert result.risk_band == "green"
    assert result.actions == []


def test_yellow_band():
    result = classify_gv(0.6)
    assert result.risk_band == "yellow"
    assert "alert" in result.actions


def test_red_band():
    result = classify_gv(0.9)
    assert result.risk_band == "red"
    assert "alert" in result.actions
    assert "require_human_review" in result.actions
