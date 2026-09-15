from app.services.counterfactual import CounterfactualAnalyzer
from app.services.risk_engine import RiskEngine


def test_counterfactual_removes_evidence_contribution() -> None:
    risk = RiskEngine().assess(
        [
            "dmarc_fail",
            "spf_fail",
            "reply_to_domain_mismatch",
        ]
    )

    result = CounterfactualAnalyzer().analyze(risk=risk)

    assert result.original_score == 55.0
    assert result.original_verdict == "medium"
    assert len(result.scenarios) == 3

    scenario = next(
        item
        for item in result.scenarios
        if item.removed_indicator == "dmarc_fail"
    )

    assert scenario.counterfactual_score == 33.0
    assert scenario.score_delta == 22.0


def test_counterfactual_scenarios_are_ranked() -> None:
    risk = RiskEngine().assess(
        [
            "dmarc_fail",
            "executable_or_script_extension",
            "behavior_urgency",
        ]
    )

    result = CounterfactualAnalyzer().analyze(risk=risk)

    assert result.scenarios[0].removed_indicator == (
        "executable_or_script_extension"
    )
    assert result.scenarios[0].score_delta == 30.0


def test_counterfactual_can_change_verdict() -> None:
    risk = RiskEngine().assess(
        [
            "dmarc_fail",
            "executable_or_script_extension",
            "behavior_urgency",
        ]
    )

    result = CounterfactualAnalyzer().analyze(risk=risk)

    scenario = next(
        item
        for item in result.scenarios
        if item.removed_indicator == "executable_or_script_extension"
    )

    assert scenario.original_score == 64.0
    assert scenario.original_verdict == "high"
    assert scenario.counterfactual_score == 34.0
    assert scenario.counterfactual_verdict == "low"