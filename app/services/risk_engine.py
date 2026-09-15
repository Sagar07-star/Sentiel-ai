"""
Sentinel AI
Explainable Risk Engine

Combines observable detector signals into a normalized risk score.

The engine distinguishes between:
- benign observations,
- weak contextual signals,
- strong risk indicators,
- machine-learning evidence,
- and high-confidence malicious attachment indicators.

A single weak URL characteristic must never be treated as a threat.
The score is an investigation aid, not a guarantee of maliciousness.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RiskFactor:
    indicator: str
    description: str
    weight: float


@dataclass(frozen=True, slots=True)
class RiskAssessment:
    score: float
    verdict: str
    confidence: float
    factors: list[RiskFactor]


class RiskEngine:
    """Calculate an explainable threat risk score."""

    STRONG_WEIGHTS = {
        "spf_fail": 18.0,
        "dkim_fail": 18.0,
        "dmarc_fail": 22.0,
        "reply_to_domain_mismatch": 15.0,
        "return_path_domain_mismatch": 12.0,
        "authentication_domain_mismatch": 15.0,
        "suspicious_keywords": 10.0,
        "ip_based_url": 18.0,
        "credential_request": 18.0,
        "behavior_credential_request": 18.0,
        "behavior_payment_request": 15.0,
        "behavior_threat_language": 12.0,
        "executable_or_script_extension": 30.0,
        "macro_capable_document": 22.0,
        "double_extension": 25.0,
        "extension_content_type_mismatch": 18.0,
        "embedded_binary_object": 12.0,
    }

    # ML evidence is intentionally bounded.
    #
    # The local classifier is an additional evidence layer, not the sole
    # authority for a threat verdict. Strong authentication, identity,
    # attachment, URL, and behavioral evidence remains primary.
    ML_WEIGHTS = {
        "ml_phishing_probability_high": 12.0,
        "ml_phishing_probability_very_high": 15.0,
        "ml_text_and_structure_correlation": 8.0,
        "ml_text_and_behavior_correlation": 6.0,
    }

    # These observations never create risk by themselves.
    CONTEXTUAL_INDICATORS = {
        "long_url",
        "deep_subdomain",
        "non_https",
        "url_shortener",
        "behavior_urgency",
        "ml_suspicious_language",
        "ml_suspicious_structure",
        "ml_behavioral_context",
    }

    # Urgency can strengthen an already suspicious investigation.
    # It must not independently create a threat verdict.
    CONTEXTUAL_BONUS = {
        "behavior_urgency": 12.0,
    }

    DESCRIPTIONS = {
        "spf_fail": "SPF authentication failure",
        "dkim_fail": "DKIM authentication failure",
        "dmarc_fail": "DMARC authentication failure",
        "reply_to_domain_mismatch": (
            "Reply-To domain differs from the visible sender domain"
        ),
        "return_path_domain_mismatch": (
            "Return-Path domain differs from the visible sender domain"
        ),
        "authentication_domain_mismatch": (
            "Authentication domain differs from the visible sender domain"
        ),
        "suspicious_keywords": "Suspicious destination keywords detected",
        "non_https": "URL does not use HTTPS",
        "ip_based_url": "URL uses an IP address instead of a conventional domain",
        "url_shortener": "URL shortening service detected",
        "long_url": (
            "URL is unusually long; treated as a contextual observation"
        ),
        "deep_subdomain": (
            "Deep subdomain structure detected; treated as contextual"
        ),
        "credential_request": "Credential request detected",
        "behavior_credential_request": (
            "Credential or account-verification language detected"
        ),
        "behavior_urgency": "Urgency or time-pressure language detected",
        "behavior_payment_request": (
            "Payment or financial-action language detected"
        ),
        "behavior_threat_language": (
            "Threat or consequence language detected"
        ),
        "executable_or_script_extension": (
            "Executable or script-capable attachment detected"
        ),
        "macro_capable_document": "Macro-capable document detected",
        "double_extension": "Suspicious double file extension detected",
        "extension_content_type_mismatch": (
            "Attachment extension and declared content type disagree"
        ),
        "embedded_binary_object": "Embedded binary MIME object detected",
        "ml_phishing_probability_high": (
            "Local machine-learning model identified elevated phishing probability"
        ),
        "ml_phishing_probability_very_high": (
            "Local machine-learning model identified very high phishing probability"
        ),
        "ml_text_and_structure_correlation": (
            "Phishing-associated language correlates with suspicious URL structure"
        ),
        "ml_text_and_behavior_correlation": (
            "Phishing-associated language correlates with social-engineering behavior"
        ),
        "ml_suspicious_language": (
            "Machine-learning analysis observed suspicious language features"
        ),
        "ml_suspicious_structure": (
            "Machine-learning analysis observed suspicious URL or domain structure"
        ),
        "ml_behavioral_context": (
            "Machine-learning analysis received corroborating behavioral evidence"
        ),
    }

    def assess(self, indicators: list[str]) -> RiskAssessment:
        """Calculate risk from unique observed indicators."""

        unique_indicators = list(dict.fromkeys(indicators))

        strong_indicators = [
            indicator
            for indicator in unique_indicators
            if indicator in self.STRONG_WEIGHTS
        ]

        ml_indicators = [
            indicator
            for indicator in unique_indicators
            if indicator in self.ML_WEIGHTS
        ]

        contextual_indicators = [
            indicator
            for indicator in unique_indicators
            if indicator in self.CONTEXTUAL_INDICATORS
        ]

        factors: list[RiskFactor] = []

        for indicator in strong_indicators:
            factors.append(
                RiskFactor(
                    indicator=indicator,
                    description=self.DESCRIPTIONS[indicator],
                    weight=self.STRONG_WEIGHTS[indicator],
                )
            )

        for indicator in ml_indicators:
            factors.append(
                RiskFactor(
                    indicator=indicator,
                    description=self.DESCRIPTIONS[indicator],
                    weight=self.ML_WEIGHTS[indicator],
                )
            )

        for indicator in contextual_indicators:
            weight = 0.0

            if strong_indicators or ml_indicators:
                weight = self.CONTEXTUAL_BONUS.get(
                    indicator,
                    0.0,
                )

            factors.append(
                RiskFactor(
                    indicator=indicator,
                    description=self.DESCRIPTIONS[indicator],
                    weight=weight,
                )
            )

        score = min(
            100.0,
            sum(factor.weight for factor in factors),
        )

        verdict = self._verdict(
            score=score,
            strong_indicator_count=len(strong_indicators),
            ml_indicator_count=len(ml_indicators),
        )

        confidence = self._confidence(
            score=score,
            strong_indicator_count=len(strong_indicators),
            ml_indicator_count=len(ml_indicators),
            contextual_indicator_count=len(contextual_indicators),
        )

        return RiskAssessment(
            score=round(score, 2),
            verdict=verdict,
            confidence=round(confidence, 2),
            factors=sorted(
                factors,
                key=lambda factor: factor.weight,
                reverse=True,
            ),
        )

    @staticmethod
    def _verdict(
        *,
        score: float,
        strong_indicator_count: int,
        ml_indicator_count: int,
    ) -> str:
        """Determine the investigation verdict."""

        # ML evidence can contribute to a verdict, but ML-only evidence
        # requires meaningful accumulated evidence before becoming a threat.
        evidence_count = (
            strong_indicator_count
            + ml_indicator_count
        )

        if evidence_count == 0:
            return "minimal"

        if score >= 80:
            return "critical"

        if score >= 60:
            return "high"

        if score >= 35:
            return "medium"

        if score >= 15:
            return "low"

        return "minimal"

    @staticmethod
    def _confidence(
        *,
        score: float,
        strong_indicator_count: int,
        ml_indicator_count: int,
        contextual_indicator_count: int,
    ) -> float:
        """Estimate confidence from risk-bearing evidence."""

        total_risk_evidence = (
            strong_indicator_count
            + ml_indicator_count
        )

        if total_risk_evidence == 0:
            if contextual_indicator_count == 0:
                return 0.20

            return min(
                0.50,
                0.30 + (contextual_indicator_count * 0.04),
            )

        # Primary forensic evidence contributes more confidence than ML.
        evidence_confidence = min(
            0.95,
            0.45
            + (strong_indicator_count * 0.08)
            + (ml_indicator_count * 0.04),
        )

        if contextual_indicator_count >= 2:
            evidence_confidence += 0.03

        if score >= 60:
            evidence_confidence += 0.03

        return min(
            evidence_confidence,
            0.98,
        )


__all__ = [
    "RiskAssessment",
    "RiskEngine",
    "RiskFactor",
]