"""
Sentinel AI
Counterfactual Threat Reasoning

Explains which evidence contributes most to a verdict and what
changes could materially reduce the assessed risk.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.risk_engine import RiskAssessment


@dataclass(frozen=True, slots=True)
class CounterfactualScenario:
    scenario_id: str
    removed_indicator: str
    original_score: float
    counterfactual_score: float
    score_delta: float
    original_verdict: str
    counterfactual_verdict: str
    explanation: str


@dataclass(frozen=True, slots=True)
class CounterfactualAnalysis:
    original_score: float
    original_verdict: str
    scenarios: list[CounterfactualScenario]


class CounterfactualAnalyzer:
    """Calculate evidence-removal scenarios."""

    def analyze(
        self,
        *,
        risk: RiskAssessment,
    ) -> CounterfactualAnalysis:
        scenarios: list[CounterfactualScenario] = []

        for factor in risk.factors:
            counterfactual_score = max(
                0.0,
                risk.score - factor.weight,
            )

            counterfactual_verdict = self._verdict(
                counterfactual_score
            )

            scenarios.append(
                CounterfactualScenario(
                    scenario_id=f"remove_{factor.indicator}",
                    removed_indicator=factor.indicator,
                    original_score=risk.score,
                    counterfactual_score=round(
                        counterfactual_score,
                        2,
                    ),
                    score_delta=round(
                        risk.score - counterfactual_score,
                        2,
                    ),
                    original_verdict=risk.verdict,
                    counterfactual_verdict=counterfactual_verdict,
                    explanation=(
                        f"If '{factor.indicator}' were removed from "
                        "the evidence set, the calculated risk would "
                        f"change from {risk.score:.2f} to "
                        f"{counterfactual_score:.2f}."
                    ),
                )
            )

        scenarios.sort(
            key=lambda scenario: scenario.score_delta,
            reverse=True,
        )

        return CounterfactualAnalysis(
            original_score=risk.score,
            original_verdict=risk.verdict,
            scenarios=scenarios,
        )

    @staticmethod
    def _verdict(score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 35:
            return "medium"
        if score >= 15:
            return "low"
        return "minimal"


__all__ = [
    "CounterfactualAnalysis",
    "CounterfactualAnalyzer",
    "CounterfactualScenario",
]