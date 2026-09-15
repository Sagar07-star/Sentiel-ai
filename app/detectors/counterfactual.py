"""
Sentinel AI
Counterfactual Threat Reasoning

Measures how much individual evidence contributes to an overall
risk score. This helps analysts understand which evidence is
actually driving a verdict.

This is an analytical aid, not proof of attacker intent.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RiskEvidence:
    evidence_id: str
    description: str
    contribution: float


@dataclass(frozen=True, slots=True)
class CounterfactualResult:
    original_score: float
    evidence_id: str
    evidence_description: str
    score_without_evidence: float
    score_change: float


class CounterfactualAnalyzer:
    """Evaluate risk sensitivity to individual evidence."""

    def analyze(
        self,
        *,
        original_score: float,
        evidence: list[RiskEvidence],
    ) -> list[CounterfactualResult]:
        if not 0.0 <= original_score <= 100.0:
            raise ValueError("Original risk score must be between 0 and 100.")

        results: list[CounterfactualResult] = []

        for item in evidence:
            contribution = max(0.0, item.contribution)

            score_without = max(
                0.0,
                min(100.0, original_score - contribution),
            )

            results.append(
                CounterfactualResult(
                    original_score=original_score,
                    evidence_id=item.evidence_id,
                    evidence_description=item.description,
                    score_without_evidence=score_without,
                    score_change=original_score - score_without,
                )
            )

        return sorted(
            results,
            key=lambda result: result.score_change,
            reverse=True,
        )


__all__ = [
    "CounterfactualAnalyzer",
    "CounterfactualResult",
    "RiskEvidence",
]