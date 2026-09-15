"""
Sentinel AI
URL Risk Analysis

Analyzes URLs locally without making network requests.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class URLRisk:
    url: str
    score: float
    findings: list[str]
    indicators: list[str]


class URLRiskAnalyzer:
    """Identify suspicious URL characteristics."""

    SUSPICIOUS_WORDS = {
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "password",
        "signin",
        "payment",
        "invoice",
        "update",
        "confirm",
    }

    SHORTENERS = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "ow.ly",
        "buff.ly",
    }

    def analyze(self, url: str) -> URLRisk:
        findings: list[str] = []
        indicators: list[str] = []
        score = 0.0

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
        except ValueError:
            return URLRisk(
                url=url,
                score=1.0,
                findings=["URL could not be parsed safely."],
                indicators=["malformed_url"],
            )

        hostname = hostname.lower().rstrip(".")

        if parsed.scheme != "https":
            score += 0.15
            findings.append("URL does not use HTTPS.")
            indicators.append("non_https")

        if self._is_ip(hostname):
            score += 0.25
            findings.append("URL uses an IP address instead of a domain.")
            indicators.append("ip_based_url")

        if "@" in parsed.netloc:
            score += 0.30
            findings.append("URL contains an embedded user-information delimiter.")
            indicators.append("userinfo_in_url")

        if len(url) > 150:
            score += 0.10
            findings.append("URL is unusually long.")
            indicators.append("long_url")

        if hostname.count(".") >= 4:
            score += 0.10
            findings.append("URL contains many subdomain levels.")
            indicators.append("deep_subdomain")

        if hostname in self.SHORTENERS:
            score += 0.20
            findings.append("URL uses a known URL-shortening service.")
            indicators.append("url_shortener")

        lower_url = url.lower()

        matched_words = [
            word
            for word in self.SUSPICIOUS_WORDS
            if re.search(rf"\b{re.escape(word)}\b", lower_url)
        ]

        if matched_words:
            score += min(0.25, 0.05 * len(matched_words))
            findings.append(
                "URL contains security-sensitive keywords: "
                + ", ".join(sorted(matched_words))
                + "."
            )
            indicators.append("suspicious_keywords")

        score = min(score, 1.0)

        return URLRisk(
            url=url,
            score=score,
            findings=findings,
            indicators=indicators,
        )

    @staticmethod
    def _is_ip(hostname: str) -> bool:
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False


__all__ = [
    "URLRisk",
    "URLRiskAnalyzer",
]