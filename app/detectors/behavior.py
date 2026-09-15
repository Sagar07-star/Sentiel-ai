"""
Sentinel AI
Behavioral Threat Analysis

Detects observable social-engineering patterns in email text.
This is one evidence layer, not a standalone phishing verdict.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BehavioralAnalysis:
    score: float
    findings: list[str]
    indicators: list[str]
    matched_patterns: list[str]


class BehavioralAnalyzer:
    """Analyze social-engineering characteristics in email content."""

    PATTERNS = {
        "urgency": (
            r"\b(urgent|immediately|right away|act now|"
            r"within \d+ hours?|expires today)\b",
            0.18,
            "Urgency or time-pressure language detected.",
        ),
        "credential_request": (
            r"\b(password|passcode|one[- ]time code|otp|"
            r"login credentials|verify your account)\b",
            0.22,
            "Credential or account-verification language detected.",
        ),
        "payment_request": (
            r"\b(payment|wire transfer|bank transfer|"
            r"gift card|invoice|pay immediately)\b",
            0.20,
            "Payment or financial-action language detected.",
        ),
        "threat_language": (
            r"\b(account will be (closed|suspended)|"
            r"legal action|penalty|fine|access will be revoked)\b",
            0.18,
            "Threat or consequence-based pressure detected.",
        ),
        "impersonation": (
            r"\b(ceo|chief executive|finance department|"
            r"it department|security team|administrator)\b",
            0.10,
            "Potential organizational impersonation language detected.",
        ),
        "secrecy": (
            r"\b(do not tell|keep this confidential|"
            r"keep this private|do not share)\b",
            0.15,
            "Secrecy or confidentiality pressure detected.",
        ),
    }

    def analyze(
        self,
        *,
        subject: str = "",
        plain_text: str = "",
        html: str = "",
    ) -> BehavioralAnalysis:
        content = f"{subject}\n{plain_text}\n{html}".lower()

        findings: list[str] = []
        indicators: list[str] = []
        matched_patterns: list[str] = []
        score = 0.0

        for name, (pattern, weight, finding) in self.PATTERNS.items():
            if re.search(pattern, content, flags=re.IGNORECASE):
                score += weight
                findings.append(finding)
                indicators.append(f"behavior_{name}")
                matched_patterns.append(name)

        return BehavioralAnalysis(
            score=min(score, 1.0),
            findings=findings,
            indicators=indicators,
            matched_patterns=matched_patterns,
        )


__all__ = [
    "BehavioralAnalysis",
    "BehavioralAnalyzer",
]