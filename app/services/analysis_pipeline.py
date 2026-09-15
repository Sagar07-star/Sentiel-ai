"""
Sentinel AI
Unified Forensic Analysis Pipeline

Connects parsing, authentication, identity, indicators, URL analysis,
infrastructure intelligence, attachment analysis, behavioral analysis,
machine-learning phishing detection, evidence correlation, attack graph,
risk scoring, timeline reconstruction, and counterfactual reasoning.

Important presentation rule:
- findings = all forensic observations
- threat_findings = materially significant security threats only
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from typing import Any

from app.detectors.authentication import AuthenticationAnalyzer
from app.detectors.behavior import BehavioralAnalyzer
from app.detectors.identity import IdentityAnalyzer
from app.detectors.ml_phishing import (
    MLPhishingAnalyzer,
    MLPhishingResult,
)
from app.detectors.url_risk import URLRiskAnalyzer
from app.extraction.indicators import IndicatorExtractor
from app.intelligence.infrastructure import InfrastructureAnalyzer
from app.parsers.attachment_forensics import AttachmentAnalyzer
from app.parsers.email_parser import EmailParser, ParsedEmail
from app.parsers.header_analyzer import HeaderAnalyzer
from app.services.attack_graph import AttackGraph, AttackGraphBuilder
from app.services.correlation import (
    CorrelatedFinding,
    EvidenceCorrelator,
)
from app.services.counterfactual import (
    CounterfactualAnalysis,
    CounterfactualAnalyzer,
)
from app.services.risk_engine import RiskAssessment, RiskEngine
from app.services.timeline import TimelineBuilder, TimelineEvent


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Complete forensic result for one email evidence item."""

    email: ParsedEmail

    indicators: list[str]
    urls: list[str]
    domains: list[str]
    ip_addresses: list[str]

    findings: list[str]
    threat_findings: list[str]

    authentication_findings: list[str]
    authentication_indicators: list[str]

    identity_findings: list[str]
    identity_indicators: list[str]

    url_findings: list[str]
    attachment_findings: list[str]
    attachment_details: list[dict[str, object]]
    behavioral_findings: list[str]

    ml_phishing: MLPhishingResult

    infrastructure: list[dict[str, object]]

    correlated_findings: list[CorrelatedFinding]

    attack_graph: AttackGraph

    risk: RiskAssessment
    counterfactual: CounterfactualAnalysis
    timeline: list[TimelineEvent]


class AnalysisPipeline:
    """Execute the complete local forensic analysis workflow."""

    def __init__(self) -> None:
        self.email_parser = EmailParser()
        self.header_analyzer = HeaderAnalyzer()
        self.authentication_analyzer = AuthenticationAnalyzer()
        self.identity_analyzer = IdentityAnalyzer()
        self.indicator_extractor = IndicatorExtractor()
        self.url_analyzer = URLRiskAnalyzer()
        self.infrastructure_analyzer = InfrastructureAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.ml_phishing_analyzer = MLPhishingAnalyzer()
        self.correlator = EvidenceCorrelator()
        self.attack_graph_builder = AttackGraphBuilder()
        self.risk_engine = RiskEngine()
        self.counterfactual_analyzer = CounterfactualAnalyzer()
        self.timeline_builder = TimelineBuilder()

    def analyze(self, data: bytes) -> PipelineResult:
        """Run the complete forensic analysis."""

        email = self.email_parser.parse(data)

        header = self.header_analyzer.analyze(
            from_header=email.sender,
            reply_to=email.reply_to,
            return_path=email.return_path,
            subject=email.subject,
            date=email.date,
            received_headers=email.received_headers,
            authentication_results=email.authentication_results,
        )

        authentication = self.authentication_analyzer.analyze(
            email.authentication_results
        )

        identity = self.identity_analyzer.analyze(
            sender_address=header.sender_address,
            reply_to_address=header.reply_to_address,
            return_path_address=header.return_path_address,
            spf_domain=authentication.spf_domain,
            dkim_domain=authentication.dkim_domain,
            dmarc_domain=authentication.dmarc_domain,
        )

        extracted = self.indicator_extractor.extract(
            plain_text=email.plain_text,
            html=email.html,
        )

        unique_urls = list(
            dict.fromkeys(extracted.urls)
        )

        unique_domains = list(
            dict.fromkeys(extracted.domains)
        )

        # --------------------------------------------------------
        # URL FORENSICS
        # --------------------------------------------------------

        url_findings: list[str] = []
        url_indicators: list[str] = []

        for url in unique_urls:
            url_result = self.url_analyzer.analyze(url)

            url_findings.extend(url_result.findings)
            url_indicators.extend(url_result.indicators)

        # --------------------------------------------------------
        # ATTACHMENT FORENSICS
        # --------------------------------------------------------

        attachment_findings: list[str] = []
        attachment_indicators: list[str] = []
        attachment_details: list[dict[str, object]] = []

        for attachment in email.attachments:
            attachment_result = self.attachment_analyzer.analyze(
                filename=attachment.filename,
                data=attachment.data,
                declared_content_type=attachment.content_type,
            )

            attachment_findings.extend(
                attachment_result.findings
            )

            attachment_indicators.extend(
                attachment_result.indicators
            )

            attachment_details.append(
                _serialize_attachment_result(
                    filename=attachment.filename,
                    content_type=attachment.content_type,
                    size_bytes=len(attachment.data),
                    result=attachment_result,
                )
            )

        # --------------------------------------------------------
        # BEHAVIOR
        # --------------------------------------------------------

        behavioral = self.behavioral_analyzer.analyze(
            subject=email.subject,
            plain_text=email.plain_text,
            html=email.html,
        )

        # --------------------------------------------------------
        # MACHINE LEARNING
        # --------------------------------------------------------

        ml_phishing = self.ml_phishing_analyzer.analyze(
            subject=email.subject,
            body=email.plain_text or email.html,
            urls=unique_urls,
            domains=unique_domains,
            behavioral_findings=behavioral.findings,
        )

        # --------------------------------------------------------
        # INFRASTRUCTURE
        # --------------------------------------------------------

        infrastructure = self.infrastructure_analyzer.analyze(
            domains=extracted.domains,
            ip_addresses=extracted.ip_addresses,
        )

        infrastructure_ips = [
            str(item["ip"])
            for item in infrastructure
            if item.get("ip")
        ]

        all_ip_addresses = list(
            dict.fromkeys(
                [
                    *extracted.ip_addresses,
                    *infrastructure_ips,
                ]
            )
        )

        # --------------------------------------------------------
        # INDICATORS
        # --------------------------------------------------------

        indicators = list(
            dict.fromkeys(
                [
                    *header.indicators,
                    *authentication.indicators,
                    *identity.indicators,
                    *url_indicators,
                    *attachment_indicators,
                    *behavioral.indicators,
                    *ml_phishing.indicators,
                ]
            )
        )

        authentication_findings = list(
            dict.fromkeys(
                authentication.findings
            )
        )

        identity_findings = list(
            dict.fromkeys(
                identity.findings
            )
        )

        behavioral_findings = list(
            dict.fromkeys(
                behavioral.findings
            )
        )

        url_findings = list(
            dict.fromkeys(
                url_findings
            )
        )

        attachment_findings = list(
            dict.fromkeys(
                attachment_findings
            )
        )

        ml_findings = list(
            dict.fromkeys(
                ml_phishing.findings
            )
        )

        # --------------------------------------------------------
        # ALL FORENSIC OBSERVATIONS
        #
        # This is deliberately broad.
        # It is NOT the threat list shown to the analyst.
        # --------------------------------------------------------

        findings = list(
            dict.fromkeys(
                [
                    *authentication_findings,
                    *identity_findings,
                    *url_findings,
                    *attachment_findings,
                    *behavioral_findings,
                    *ml_findings,
                ]
            )
        )

        # --------------------------------------------------------
        # CORRELATION
        # --------------------------------------------------------

        correlated = self.correlator.correlate(
            indicators=indicators,
        )

        # --------------------------------------------------------
        # SERIOUS THREATS
        #
        # Only material security findings enter this collection.
        # Generic informational/negative ML observations and weak
        # URL heuristics are intentionally excluded.
        # --------------------------------------------------------

        threat_findings = _build_serious_threats(
            authentication_findings=authentication_findings,
            identity_findings=identity_findings,
            url_findings=url_findings,
            attachment_findings=attachment_findings,
            behavioral_findings=behavioral_findings,
            ml_phishing=ml_phishing,
            correlated_findings=correlated,
        )

        # --------------------------------------------------------
        # ATTACK GRAPH
        # --------------------------------------------------------

        attack_graph = self.attack_graph_builder.build(
            sender=header.sender_address,
            reply_to=header.reply_to_address,
            return_path=header.return_path_address,
            domains=unique_domains,
            urls=unique_urls,
            ip_addresses=all_ip_addresses,
            indicators=indicators,
            attachment_findings=attachment_findings,
            behavioral_findings=behavioral_findings,
        )

        # --------------------------------------------------------
        # RISK
        # --------------------------------------------------------

        risk = self.risk_engine.assess(
            indicators=indicators,
        )

        counterfactual = self.counterfactual_analyzer.analyze(
            risk=risk,
        )

        # --------------------------------------------------------
        # TIMELINE
        # --------------------------------------------------------

        timeline = self.timeline_builder.build(
            email_date=email.date,
            received_hops=[
                {
                    "timestamp": hop.timestamp,
                    "from_host": hop.from_host,
                }
                for hop in header.received_hops
            ],
            authentication_events=[],
        )

        return PipelineResult(
            email=email,
            indicators=indicators,
            urls=unique_urls,
            domains=unique_domains,
            ip_addresses=all_ip_addresses,
            findings=findings,
            threat_findings=threat_findings,
            authentication_findings=authentication_findings,
            authentication_indicators=list(
                dict.fromkeys(
                    authentication.indicators
                )
            ),
            identity_findings=identity_findings,
            identity_indicators=list(
                dict.fromkeys(
                    identity.indicators
                )
            ),
            url_findings=url_findings,
            attachment_findings=attachment_findings,
            attachment_details=attachment_details,
            behavioral_findings=behavioral_findings,
            ml_phishing=ml_phishing,
            infrastructure=infrastructure,
            correlated_findings=correlated,
            attack_graph=attack_graph,
            risk=risk,
            counterfactual=counterfactual,
            timeline=timeline,
        )


# ============================================================
# THREAT CLASSIFICATION
# ============================================================

def _build_serious_threats(
    *,
    authentication_findings: list[str],
    identity_findings: list[str],
    url_findings: list[str],
    attachment_findings: list[str],
    behavioral_findings: list[str],
    ml_phishing: MLPhishingResult,
    correlated_findings: list[CorrelatedFinding],
) -> list[str]:
    """
    Build the analyst-facing serious threat list.

    Important:
    This does NOT simply copy every forensic observation.

    Examples deliberately excluded:
        "URL is unusually long."
        "The local machine-learning model did not identify
         strong phishing language evidence."

    Those remain available as forensic observations but are not
    presented as threats.
    """

    threats: list[str] = []

    # --------------------------------------------------------
    # Strong authentication failures
    # --------------------------------------------------------

    for finding in authentication_findings:
        text = finding.lower()

        if any(
            keyword in text
            for keyword in (
                "spf fail",
                "spf softfail",
                "dkim fail",
                "dmarc fail",
                "authentication failed",
                "authentication failure",
            )
        ):
            threats.append(finding)

    # --------------------------------------------------------
    # Identity deception
    # --------------------------------------------------------

    for finding in identity_findings:
        text = finding.lower()

        if any(
            keyword in text
            for keyword in (
                "reply-to mismatch",
                "reply-to differs",
                "return-path mismatch",
                "return-path differs",
                "sender mismatch",
                "domain mismatch",
                "authentication domain mismatch",
                "impersonat",
            )
        ):
            threats.append(finding)

    # --------------------------------------------------------
    # Dangerous URL indicators
    #
    # Long URL alone is intentionally NOT sufficient.
    # --------------------------------------------------------

    for finding in url_findings:
        text = finding.lower()

        if _is_serious_url_finding(text):
            threats.append(finding)

    # --------------------------------------------------------
    # Dangerous attachment findings
    # --------------------------------------------------------

    for finding in attachment_findings:
        text = finding.lower()

        if _is_serious_attachment_finding(text):
            threats.append(finding)

    # --------------------------------------------------------
    # Strong social-engineering findings
    # --------------------------------------------------------

    for finding in behavioral_findings:
        text = finding.lower()

        if _is_serious_behavior_finding(text):
            threats.append(finding)

    # --------------------------------------------------------
    # ML:
    #
    # ONLY positive strong phishing evidence becomes a threat.
    #
    # "did not identify strong phishing language" is excluded.
    # --------------------------------------------------------

    if (
        getattr(
            ml_phishing,
            "probability",
            0.0,
        )
        >= 0.85
    ):
        positive_ml = _extract_positive_ml_finding(
            ml_phishing
        )

        if positive_ml:
            threats.append(positive_ml)

    # --------------------------------------------------------
    # Correlated findings are the strongest source because they
    # represent multiple evidence layers agreeing.
    # --------------------------------------------------------

    for finding in correlated_findings:
        severity = str(
            finding.severity
        ).lower()

        if severity in {
            "critical",
            "high",
        }:
            threats.append(
                finding.title
            )

    return list(
        dict.fromkeys(
            threat
            for threat in threats
            if _is_displayable_threat(threat)
        )
    )


def _is_serious_url_finding(text: str) -> bool:
    """Return True only for materially dangerous URL findings."""

    if "unusually long" in text:
        return False

    if "long url" in text:
        return False

    if "url length" in text:
        return False

    serious_patterns = (
        "ip address",
        "credential",
        "login",
        "password",
        "phishing",
        "malicious",
        "suspicious redirect",
        "redirect chain",
        "punycode",
        "homograph",
        "lookalike",
        "encoded",
        "javascript:",
        "data:",
    )

    return any(
        pattern in text
        for pattern in serious_patterns
    )


def _is_serious_attachment_finding(text: str) -> bool:
    """Return True for dangerous static attachment observations."""

    serious_patterns = (
        "executable",
        "macro",
        "embedded object",
        "embedded binary",
        "script",
        "powershell",
        "javascript",
        "double extension",
        "extension mismatch",
        "content-type mismatch",
        "signature mismatch",
        "suspicious archive",
        "malicious archive",
        "dangerous archive",
    )

    return any(
        pattern in text
        for pattern in serious_patterns
    )


def _is_serious_behavior_finding(text: str) -> bool:
    """Return True for strong social-engineering observations."""

    serious_patterns = (
        "credential",
        "password",
        "payment",
        "wire transfer",
        "financial",
        "threat",
        "impersonat",
        "account compromise",
        "security verification",
        "urgent account",
    )

    return any(
        pattern in text
        for pattern in serious_patterns
    )


def _extract_positive_ml_finding(
    ml_phishing: MLPhishingResult,
) -> str | None:
    """Extract a positive ML phishing finding only."""

    findings = getattr(
        ml_phishing,
        "findings",
        [],
    )

    for finding in findings:
        text = str(finding)

        lowered = text.lower()

        if any(
            negative in lowered
            for negative in (
                "did not identify",
                "no strong",
                "not identify",
                "low phishing",
                "weak phishing",
                "insufficient",
            )
        ):
            continue

        return text

    return None


def _is_displayable_threat(value: str) -> bool:
    """
    Final safety filter for analyst-facing threats.

    Prevents raw URLs and informational ML messages from
    accidentally appearing as threats.
    """

    text = str(value).strip()

    if not text:
        return False

    lowered = text.lower()

    if "did not identify strong phishing" in lowered:
        return False

    if "did not identify" in lowered:
        return False

    if "no strong phishing" in lowered:
        return False

    if "unusually long" in lowered:
        return False

    if lowered.startswith("http://"):
        return False

    if lowered.startswith("https://"):
        return False

    return True


# ============================================================
# ATTACHMENT SERIALIZATION
# ============================================================

def _serialize_attachment_result(
    *,
    filename: str,
    content_type: str,
    size_bytes: int,
    result: object,
) -> dict[str, object]:
    """
    Convert the attachment forensic result into safe structured
    data for the API.

    Raw attachment bytes are NEVER returned.
    """

    payload: dict[str, object] = {
        "filename": filename,
        "declared_content_type": content_type,
        "size_bytes": size_bytes,
    }

    if is_dataclass(result) and not isinstance(
        result,
        type,
    ):
        raw: Any = asdict(result)
        payload.update(
            _remove_attachment_bytes(raw)
        )

    elif isinstance(result, dict):
        payload.update(
            _remove_attachment_bytes(result)
        )

    else:
        payload["findings"] = list(
            getattr(
                result,
                "findings",
                [],
            )
        )

        payload["indicators"] = list(
            getattr(
                result,
                "indicators",
                [],
            )
        )

    return payload


def _remove_attachment_bytes(
    value: Any,
) -> Any:
    """
    Recursively remove raw binary attachment content from
    anything exposed through the API.
    """

    if isinstance(value, bytes):
        return None

    if isinstance(value, dict):
        return {
            str(key): _remove_attachment_bytes(item)
            for key, item in value.items()
            if key not in {
                "data",
                "content",
                "raw_bytes",
                "bytes",
            }
        }

    if isinstance(value, list):
        return [
            _remove_attachment_bytes(item)
            for item in value
        ]

    if isinstance(value, tuple):
        return [
            _remove_attachment_bytes(item)
            for item in value
        ]

    return value


__all__ = [
    "AnalysisPipeline",
    "PipelineResult",
]