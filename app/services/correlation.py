"""
Sentinel AI
Cross-Layer Evidence Correlation

Combines independent observable indicators into higher-level
investigation findings.

Correlation increases confidence when multiple evidence layers
support the same hypothesis. It does not establish attribution.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CorrelatedFinding:
    finding_id: str
    title: str
    description: str
    severity: str
    confidence: float
    supporting_indicators: list[str]


class EvidenceCorrelator:
    """Correlate independent detector signals."""

    def correlate(
        self,
        *,
        indicators: list[str],
    ) -> list[CorrelatedFinding]:
        normalized = set(indicators)
        findings: list[CorrelatedFinding] = []

        if {
            "spf_fail",
            "reply_to_domain_mismatch",
        }.issubset(normalized):
            findings.append(
                CorrelatedFinding(
                    finding_id="identity_authentication_conflict",
                    title="Identity and authentication conflict",
                    description=(
                        "Authentication failure and Reply-To "
                        "domain inconsistency were observed together."
                    ),
                    severity="high",
                    confidence=0.88,
                    supporting_indicators=[
                        "spf_fail",
                        "reply_to_domain_mismatch",
                    ],
                )
            )

        if {
            "suspicious_keywords",
            "behavior_credential_request",
        }.issubset(normalized):
            findings.append(
                CorrelatedFinding(
                    finding_id="credential_harvesting_pattern",
                    title="Potential credential-harvesting pattern",
                    description=(
                        "Suspicious URL characteristics occur together "
                        "with credential or account-verification language."
                    ),
                    severity="high",
                    confidence=0.86,
                    supporting_indicators=[
                        "suspicious_keywords",
                        "behavior_credential_request",
                    ],
                )
            )

        if {
            "url_shortener",
            "behavior_urgency",
        }.issubset(normalized):
            findings.append(
                CorrelatedFinding(
                    finding_id="urgent_redirect_pattern",
                    title="Urgent redirect pattern",
                    description=(
                        "Urgency language is combined with a "
                        "shortened destination URL."
                    ),
                    severity="medium",
                    confidence=0.78,
                    supporting_indicators=[
                        "url_shortener",
                        "behavior_urgency",
                    ],
                )
            )

        if {
            "executable_or_script_extension",
            "behavior_urgency",
        }.issubset(normalized):
            findings.append(
                CorrelatedFinding(
                    finding_id="urgent_malicious_attachment_pattern",
                    title="Urgent executable attachment pattern",
                    description=(
                        "Urgency language is combined with an executable "
                        "or script-capable attachment."
                    ),
                    severity="critical",
                    confidence=0.93,
                    supporting_indicators=[
                        "executable_or_script_extension",
                        "behavior_urgency",
                    ],
                )
            )

        if {
            "dmarc_fail",
            "authentication_domain_mismatch",
        }.issubset(normalized):
            findings.append(
                CorrelatedFinding(
                    finding_id="authentication_identity_conflict",
                    title="Authentication and identity conflict",
                    description=(
                        "DMARC failure is accompanied by a mismatch "
                        "between authentication and visible identity."
                    ),
                    severity="high",
                    confidence=0.91,
                    supporting_indicators=[
                        "dmarc_fail",
                        "authentication_domain_mismatch",
                    ],
                )
            )

        return findings


__all__ = [
    "CorrelatedFinding",
    "EvidenceCorrelator",
]