from app.services.correlation import EvidenceCorrelator
from app.services.report_generator import ForensicReportGenerator
from app.services.risk_engine import RiskEngine
from app.services.timeline import TimelineBuilder


def test_forensic_report_generation() -> None:
    risk = RiskEngine().assess(
        [
            "dmarc_fail",
            "reply_to_domain_mismatch",
            "behavior_credential_request",
        ]
    )

    correlations = EvidenceCorrelator().correlate(
        indicators=[
            "dmarc_fail",
            "reply_to_domain_mismatch",
            "behavior_credential_request",
            "suspicious_keywords",
        ]
    )

    timeline = TimelineBuilder().build(
        email_date="2026-09-03T12:00:00+00:00",
    )

    report = ForensicReportGenerator().generate(
        investigation_id="CASE-TEST123",
        evidence_sha256="a" * 64,
        risk=risk,
        findings=[
            "DMARC authentication failed.",
            "Reply-To domain differs from sender.",
        ],
        indicators=[
            "dmarc_fail",
            "reply_to_domain_mismatch",
            "behavior_credential_request",
        ],
        correlated_findings=correlations,
        timeline=timeline,
    )

    assert report.investigation_id == "CASE-TEST123"
    assert report.verdict == risk.verdict
    assert report.risk_score == risk.score
    assert report.confidence == risk.confidence
    assert "SHA-256" in report.evidence_integrity
    assert report.executive_summary
    assert report.counterfactual_questions


def test_counterfactual_reasoning_is_present() -> None:
    risk = RiskEngine().assess(
        [
            "dmarc_fail",
            "ip_based_url",
        ]
    )

    report = ForensicReportGenerator().generate(
        investigation_id="CASE-COUNTERFACTUAL",
        evidence_sha256="b" * 64,
        risk=risk,
        findings=[],
        indicators=[
            "dmarc_fail",
            "ip_based_url",
        ],
        correlated_findings=[],
        timeline=[],
    )

    assert len(report.counterfactual_questions) >= 2
    assert any(
        "DMARC" in question
        for question in report.counterfactual_questions
    )
    assert any(
        "URL" in question
        for question in report.counterfactual_questions
    )


def test_report_deduplicates_indicators() -> None:
    risk = RiskEngine().assess(["dmarc_fail"])

    report = ForensicReportGenerator().generate(
        investigation_id="CASE-DEDUPE",
        evidence_sha256="c" * 64,
        risk=risk,
        findings=[],
        indicators=[
            "dmarc_fail",
            "dmarc_fail",
            "dmarc_fail",
        ],
        correlated_findings=[],
        timeline=[],
    )

    assert report.indicators == ["dmarc_fail"]