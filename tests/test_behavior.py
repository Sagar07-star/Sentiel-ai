from app.detectors.behavior import BehavioralAnalyzer


def test_credential_phishing_language() -> None:
    analyzer = BehavioralAnalyzer()

    result = analyzer.analyze(
        subject="Urgent account verification",
        plain_text=(
            "Verify your account immediately. "
            "Enter your password and one-time code."
        ),
    )

    assert result.score > 0.0
    assert "behavior_urgency" in result.indicators
    assert "behavior_credential_request" in result.indicators


def test_payment_pressure() -> None:
    analyzer = BehavioralAnalyzer()

    result = analyzer.analyze(
        plain_text=(
            "Please complete the payment immediately "
            "or your account will be suspended."
        ),
    )

    assert "behavior_payment_request" in result.indicators
    assert "behavior_threat_language" in result.indicators


def test_benign_message() -> None:
    analyzer = BehavioralAnalyzer()

    result = analyzer.analyze(
        subject="Team lunch",
        plain_text="See you tomorrow at noon.",
    )

    assert result.score == 0.0
    assert result.indicators == []