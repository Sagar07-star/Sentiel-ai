"""
Sentinel AI
Forensic Email Header Analyzer

Analyzes email routing and identity-related headers without making
unsupported attribution claims.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from email.utils import parseaddr


@dataclass(slots=True)
class ReceivedHop:
    """One hop in the email's Received header chain."""

    raw: str
    from_host: str | None
    by_host: str | None
    timestamp: str | None


@dataclass(slots=True)
class HeaderAnalysis:
    """Structured forensic findings from email headers."""

    from_header: str
    sender_address: str | None
    sender_domain: str | None

    reply_to: str | None
    reply_to_address: str | None
    reply_to_domain: str | None

    return_path: str | None
    return_path_address: str | None
    return_path_domain: str | None

    subject: str
    date: str | None

    received_hops: list[ReceivedHop]

    authentication_results: str | None

    findings: list[str]
    indicators: list[str]


class HeaderAnalyzer:
    """Analyze identity and routing information in parsed email headers."""

    def analyze(
        self,
        *,
        from_header: str,
        reply_to: str | None,
        return_path: str | None,
        subject: str,
        date: str | None,
        received_headers: list[str],
        authentication_results: str | None,
    ) -> HeaderAnalysis:
        """Perform deterministic header analysis."""
        sender_address = self._extract_address(from_header)
        sender_domain = self._extract_domain(sender_address)

        reply_to_address = self._extract_address(reply_to or "")
        reply_to_domain = self._extract_domain(reply_to_address)

        return_path_address = self._extract_address(
            return_path or "",
        )
        return_path_domain = self._extract_domain(
            return_path_address,
        )

        received_hops = [
            self._parse_received_header(header)
            for header in received_headers
        ]

        findings: list[str] = []
        indicators: list[str] = []

        self._analyze_identity_relationship(
            sender_domain=sender_domain,
            reply_to_domain=reply_to_domain,
            return_path_domain=return_path_domain,
            findings=findings,
            indicators=indicators,
        )

        self._analyze_received_chain(
            received_hops=received_hops,
            findings=findings,
            indicators=indicators,
        )

        self._analyze_authentication(
            authentication_results=authentication_results,
            findings=findings,
            indicators=indicators,
        )

        return HeaderAnalysis(
            from_header=from_header,
            sender_address=sender_address,
            sender_domain=sender_domain,
            reply_to=reply_to,
            reply_to_address=reply_to_address,
            reply_to_domain=reply_to_domain,
            return_path=return_path,
            return_path_address=return_path_address,
            return_path_domain=return_path_domain,
            subject=subject,
            date=date,
            received_hops=received_hops,
            authentication_results=authentication_results,
            findings=findings,
            indicators=indicators,
        )

    @staticmethod
    def _extract_address(value: str) -> str | None:
        """Extract a mailbox address from a header value."""
        if not value:
            return None

        _, address = parseaddr(value)

        address = address.strip().lower()

        if not address or "@" not in address:
            return None

        local, domain = address.rsplit("@", 1)

        if not local or not domain:
            return None

        return address

    @staticmethod
    def _extract_domain(address: str | None) -> str | None:
        """Extract the domain portion of a mailbox address."""
        if not address or "@" not in address:
            return None

        return address.rsplit("@", 1)[1].lower().rstrip(".")

    @staticmethod
    def _parse_received_header(
        header: str,
    ) -> ReceivedHop:
        """
        Parse the common structure of a Received header.

        This intentionally extracts only observable routing metadata.
        """
        from_match = re.search(
            r"\bfrom\s+([^\s(;,]+)",
            header,
            flags=re.IGNORECASE,
        )

        by_match = re.search(
            r"\bby\s+([^\s(;,]+)",
            header,
            flags=re.IGNORECASE,
        )

        timestamp = None

        if ";" in header:
            timestamp = header.rsplit(";", 1)[1].strip()

        return ReceivedHop(
            raw=header,
            from_host=(
                from_match.group(1).strip()
                if from_match
                else None
            ),
            by_host=(
                by_match.group(1).strip()
                if by_match
                else None
            ),
            timestamp=timestamp,
        )

    @staticmethod
    def _same_or_subdomain(
        left: str | None,
        right: str | None,
    ) -> bool:
        """Check whether two domains are equal or hierarchically related."""
        if not left or not right:
            return False

        left = left.lower().rstrip(".")
        right = right.lower().rstrip(".")

        return (
            left == right
            or left.endswith(f".{right}")
            or right.endswith(f".{left}")
        )

    def _analyze_identity_relationship(
        self,
        *,
        sender_domain: str | None,
        reply_to_domain: str | None,
        return_path_domain: str | None,
        findings: list[str],
        indicators: list[str],
    ) -> None:
        """Identify observable identity mismatches."""
        if (
            sender_domain
            and reply_to_domain
            and not self._same_or_subdomain(
                sender_domain,
                reply_to_domain,
            )
        ):
            findings.append(
                "Reply-To domain differs from the sender domain."
            )
            indicators.append(
                "reply_to_domain_mismatch"
            )

        if (
            sender_domain
            and return_path_domain
            and not self._same_or_subdomain(
                sender_domain,
                return_path_domain,
            )
        ):
            findings.append(
                "Return-Path domain differs from the sender domain."
            )
            indicators.append(
                "return_path_domain_mismatch"
            )

    @staticmethod
    def _analyze_received_chain(
        *,
        received_hops: list[ReceivedHop],
        findings: list[str],
        indicators: list[str],
    ) -> None:
        """Analyze basic routing-chain structure."""
        if not received_hops:
            findings.append(
                "No Received headers were available for analysis."
            )
            indicators.append(
                "missing_received_chain"
            )
            return

        if len(received_hops) == 1:
            findings.append(
                "Only one Received hop is available."
            )

        hosts = [
            hop.from_host
            for hop in received_hops
            if hop.from_host
        ]

        if len(hosts) != len(set(hosts)):
            findings.append(
                "Repeated routing hosts were observed in the "
                "Received chain."
            )
            indicators.append(
                "repeated_received_host"
            )

    @staticmethod
    def _analyze_authentication(
        *,
        authentication_results: str | None,
        findings: list[str],
        indicators: list[str],
    ) -> None:
        """Extract high-level authentication observations."""
        if not authentication_results:
            findings.append(
                "No Authentication-Results header was available."
            )
            indicators.append(
                "missing_authentication_results"
            )
            return

        normalized = authentication_results.lower()

        if re.search(r"\bspf\s*=\s*fail\b", normalized):
            findings.append("SPF authentication reports fail.")
            indicators.append("spf_fail")

        if re.search(r"\bdkim\s*=\s*fail\b", normalized):
            findings.append("DKIM authentication reports fail.")
            indicators.append("dkim_fail")

        if re.search(r"\bdmarc\s*=\s*fail\b", normalized):
            findings.append("DMARC authentication reports fail.")
            indicators.append("dmarc_fail")

        if re.search(r"\bspf\s*=\s*pass\b", normalized):
            findings.append("SPF authentication reports pass.")

        if re.search(r"\bdkim\s*=\s*pass\b", normalized):
            findings.append("DKIM authentication reports pass.")

        if re.search(r"\bdmarc\s*=\s*pass\b", normalized):
            findings.append("DMARC authentication reports pass.")


__all__ = [
    "HeaderAnalysis",
    "HeaderAnalyzer",
    "ReceivedHop",
]