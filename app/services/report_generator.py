"""
Sentinel AI
Forensic Report Generator

Produces a structured, analyst-readable forensic investigation report.
The report separates observed evidence from inferred conclusions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from app.services.correlation import CorrelatedFinding
from app.services.risk_engine import RiskAssessment
from app.services.timeline import TimelineEvent


@dataclass(frozen=True, slots=True)
class ForensicReport:
    investigation_id: str
    generated_at: datetime
    verdict: str
    risk_score: float
    confidence: float
    executive_summary: str
    evidence_integrity: str
    findings: list[str]
    indicators: list[str]
    correlated_findings: list[CorrelatedFinding]
    timeline: list[TimelineEvent]
    counterfactual_questions: list[str]


class ForensicReportGenerator:
    """Generate deterministic forensic investigation reports."""

    def generate(
        self,
        *,
        investigation_id: str,
        evidence_sha256: str,
        risk: RiskAssessment,
        findings: list[str],
        indicators: list[str],
        correlated_findings: list[CorrelatedFinding],
        timeline: list[TimelineEvent],
    ) -> ForensicReport:
        executive_summary = self._summary(
            verdict=risk.verdict,
            score=risk.score,
            confidence=risk.confidence,
            finding_count=len(findings),
            correlation_count=len(correlated_findings),
        )

        counterfactual_questions = self._counterfactual_questions(
            risk=risk,
            indicators=indicators,
        )

        return ForensicReport(
            investigation_id=investigation_id,
            generated_at=datetime.now(UTC),
            verdict=risk.verdict,
            risk_score=risk.score,
            confidence=risk.confidence,
            executive_summary=executive_summary,
            evidence_integrity=(
                f"Evidence preserved with SHA-256: {evidence_sha256}"
            ),
            findings=list(findings),
            indicators=list(dict.fromkeys(indicators)),
            correlated_findings=list(correlated_findings),
            timeline=list(timeline),
            counterfactual_questions=counterfactual_questions,
        )

    @staticmethod
    def _summary(
        *,
        verdict: str,
        score: float,
        confidence: float,
        finding_count: int,
        correlation_count: int,
    ) -> str:
        return (
            f"Sentinel AI assessed this investigation as {verdict} risk "
            f"with a score of {score:.2f}/100 and confidence of "
            f"{confidence:.2f}. "
            f"{finding_count} observable finding(s) and "
            f"{correlation_count} cross-layer correlation(s) "
            "support the assessment."
        )

    @staticmethod
    def _counterfactual_questions(
        *,
        risk: RiskAssessment,
        indicators: list[str],
    ) -> list[str]:
        questions: list[str] = []

        strongest_factor = risk.factors[0] if risk.factors else None

        if strongest_factor:
            questions.append(
                "What evidence would remove or substantially reduce "
                f"the contribution from '{strongest_factor.indicator}'?"
            )

        if "dmarc_fail" in indicators:
            questions.append(
                "Would the risk assessment change if DMARC independently "
                "validated the visible sender domain?"
            )

        if "reply_to_domain_mismatch" in indicators:
            questions.append(
                "Would the identity concern change if Reply-To matched "
                "the visible sender domain?"
            )

        if "ip_based_url" in indicators:
            questions.append(
                "Would the URL risk decrease if the destination resolved "
                "to a stable domain with trusted infrastructure?"
            )

        if not questions:
            questions.append(
                "What additional independent evidence would increase "
                "or decrease confidence in this assessment?"
            )

        return questions


__all__ = [
    "ForensicReport",
    "ForensicReportGenerator",
]