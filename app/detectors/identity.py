
"""
Sentinel AI
Sender Identity Forensics

Correlates observable sender, Reply-To, Return-Path, and authentication
domains. This module identifies inconsistencies; it does not attribute
messages to a specific attacker.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IdentityAnalysis:
    sender_address: str | None
    sender_domain: str | None
    reply_to_address: str | None
    reply_to_domain: str | None
    return_path_address: str | None
    return_path_domain: str | None
    authentication_domains: list[str]
    findings: list[str]
    indicators: list[str]


class IdentityAnalyzer:
    """Analyze relationships between email identity fields."""

    def analyze(
        self,
        *,
        sender_address: str | None,
        reply_to_address: str | None,
        return_path_address: str | None,
        spf_domain: str | None = None,
        dkim_domain: str | None = None,
        dmarc_domain: str | None = None,
    ) -> IdentityAnalysis:
        sender_domain = self._domain(sender_address)
        reply_to_domain = self._domain(reply_to_address)
        return_path_domain = self._domain(return_path_address)

        authentication_domains = list(
            dict.fromkeys(
                domain.lower().rstrip(".")
                for domain in (
                    spf_domain,
                    dkim_domain,
                    dmarc_domain,
                )
                if domain
            )
        )

        findings: list[str] = []
        indicators: list[str] = []

        self._compare(
            sender_domain,
            reply_to_domain,
            "Reply-To",
            "reply_to_domain_mismatch",
            findings,
            indicators,
        )

        self._compare(
            sender_domain,
            return_path_domain,
            "Return-Path",
            "return_path_domain_mismatch",
            findings,
            indicators,
        )

        for auth_domain in authentication_domains:
            if (
                sender_domain
                and not self._related(
                    sender_domain,
                    auth_domain,
                )
            ):
                findings.append(
                    f"Authentication domain {auth_domain} differs from "
                    f"the visible sender domain {sender_domain}."
                )
                indicators.append(
                    "authentication_domain_mismatch"
                )

        if not sender_domain:
            findings.append(
                "No valid sender domain was available."
            )
            indicators.append(
                "sender_domain_missing"
            )

        return IdentityAnalysis(
            sender_address=sender_address,
            sender_domain=sender_domain,
            reply_to_address=reply_to_address,
            reply_to_domain=reply_to_domain,
            return_path_address=return_path_address,
            return_path_domain=return_path_domain,
            authentication_domains=authentication_domains,
            findings=list(dict.fromkeys(findings)),
            indicators=list(dict.fromkeys(indicators)),
        )

    @staticmethod
    def _domain(
        address: str | None,
    ) -> str | None:
        """Extract and normalize an email address domain."""

        if not address or "@" not in address:
            return None

        domain = (
            address
            .rsplit("@", 1)[1]
            .strip()
            .lower()
            .rstrip(".")
        )

        return domain or None

    @staticmethod
    def _related(
        left: str,
        right: str,
    ) -> bool:
        """
        Determine whether two domains are equal or parent/subdomains.

        Examples:
            example.com <-> example.com       = related
            mail.example.com <-> example.com  = related
            example.com <-> attacker.com      = unrelated
        """

        left = left.lower().rstrip(".")
        right = right.lower().rstrip(".")

        return (
            left == right
            or left.endswith(f".{right}")
            or right.endswith(f".{left}")
        )

    def _compare(
        self,
        sender_domain: str | None,
        other_domain: str | None,
        field_name: str,
        indicator: str,
        findings: list[str],
        indicators: list[str],
    ) -> None:
        """Compare a secondary identity domain against the sender."""

        if not other_domain:
            return

        if sender_domain and not self._related(
            sender_domain,
            other_domain,
        ):
            findings.append(
                f"{field_name} domain differs from the visible "
                f"sender domain."
            )
            indicators.append(indicator)


__all__ = [
    "IdentityAnalysis",
    "IdentityAnalyzer",
]

