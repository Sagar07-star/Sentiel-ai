from app.services.risk_engine import RiskEngine


def test_high_risk_assessment() -> None:
    engine = RiskEngine()

    result = engine.assess(
        [
            "spf_fail",
            "dmarc_fail",
            "reply_to_domain_mismatch",
            "behavior_credential_request",
            "ip_based_url",
        ]
    )

    assert result.score == 91.0
    assert result.verdict == "critical"
    assert result.confidence > 0.5
    assert result.factors


def test_executable_attachment_creates_high_risk() -> None:
    engine = RiskEngine()

    result = engine.assess(
        [
            "executable_or_script_extension",
            "behavior_urgency",
        ]
    )

    assert result.score >= 40
    assert result.factors[0].indicator == "executable_or_script_extension"


def test_empty_evidence_has_low_confidence() -> None:
    engine = RiskEngine()

    result = engine.assess([])

    assert result.score == 0.0
    assert result.verdict == "minimal"
    assert result.confidence == 0.20


def test_duplicate_indicators_count_once() -> None:
    engine = RiskEngine()

    result = engine.assess(
        [
            "dmarc_fail",
            "dmarc_fail",
            "dmarc_fail",
        ]
    )

    assert result.score == 22.0
    assert len(result.factors) == 1