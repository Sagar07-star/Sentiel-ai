"""
Sentinel AI
Machine-Learning Phishing Detector Tests
"""

from app.detectors.ml_phishing import MLPhishingAnalyzer


def test_ml_detector_initializes() -> None:
    analyzer = MLPhishingAnalyzer()

    result = analyzer.analyze(
        subject="Team meeting tomorrow",
        body="Please review the agenda before the meeting.",
    )

    assert result.model_version == "sentinel-local-phishing-v1"
    assert result.trained_samples == 48
    assert 0.0 <= result.phishing_probability <= 1.0
    assert 0.0 <= result.benign_probability <= 1.0
    assert 0.0 <= result.confidence <= 1.0


def test_ml_detector_identifies_phishing_language() -> None:
    analyzer = MLPhishingAnalyzer()

    result = analyzer.analyze(
        subject="URGENT: Verify your account",
        body=(
            "Your account will be suspended immediately. "
            "Click the link below and confirm your password."
        ),
    )

    assert result.label == "phishing"
    assert result.phishing_probability >= 0.65
    assert "ml_phishing_probability_high" in result.indicators
    assert result.text_features


def test_ml_detector_handles_benign_message() -> None:
    analyzer = MLPhishingAnalyzer()

    result = analyzer.analyze(
        subject="Project meeting notes",
        body=(
            "Thanks for attending today's meeting. "
            "The project notes are attached for review."
        ),
    )

    assert result.label == "benign"
    assert result.benign_probability > result.phishing_probability


def test_ml_detector_detects_unseen_url_structure() -> None:
    analyzer = MLPhishingAnalyzer()

    result = analyzer.analyze(
        subject="Please review this",
        body="Open the following website.",
        urls=[
            "http://198.51.100.77/account/login/verify"
        ],
        domains=[
            "login.verify.account.example.invalid"
        ],
    )

    assert "non_https_url" in result.structural_features
    assert "ip_based_url" in result.structural_features
    assert "suspicious_url_keyword" in result.structural_features
    assert "deep_domain" in result.structural_features
    assert "ml_suspicious_structure" in result.indicators


def test_ml_detector_correlates_text_and_structure() -> None:
    analyzer = MLPhishingAnalyzer()

    result = analyzer.analyze(
        subject="Security alert: verify your password",
        body=(
            "Your account is suspended. "
            "Confirm your credentials immediately."
        ),
        urls=[
            "http://198.51.100.77/login/verify"
        ],
        domains=[
            "secure.login.verify.example.invalid"
        ],
    )

    assert result.label == "phishing"
    assert "ml_text_and_structure_correlation" in result.indicators
    assert "ml_suspicious_language" in result.indicators
    assert "ml_suspicious_structure" in result.indicators


def test_ml_detector_correlates_behavior() -> None:
    analyzer = MLPhishingAnalyzer()

    result = analyzer.analyze(
        subject="Urgent account verification",
        body="Verify your password immediately.",
        behavioral_findings=[
            "Credential request detected",
        ],
    )

    assert result.label == "phishing"
    assert "ml_behavioral_context" in result.indicators
    assert "ml_text_and_behavior_correlation" in result.indicators


def test_ml_detector_reports_insufficient_text() -> None:
    analyzer = MLPhishingAnalyzer()

    result = analyzer.analyze()

    assert result.label == "insufficient_evidence"
    assert result.phishing_probability == 0.0
    assert result.benign_probability == 0.0
    assert result.confidence == 0.0
    assert "ml_text_missing" in result.indicators