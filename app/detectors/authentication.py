"""
Sentinel AI
Email Authentication Forensics

Analyzes SPF, DKIM, and DMARC results reported by the message's
Authentication-Results headers.

This module reports observable authentication evidence only.
It does not infer attacker identity or independently validate DNS
records/signatures.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuthenticationResult:
    """Structured authentication findings."""

    spf: str | None
    dkim: str | None
    dmarc: str | None

    spf_domain: str | None
    dkim_domain: str | None
    dmarc_domain: str | None

    passed: bool
    failed: bool
    missing: bool

    findings: list[str]
    indicators: list[str]


class AuthenticationAnalyzer:
    """Analyze Authentication-Results values."""

    _RESULT_PATTERN = re.compile(
        r"\b(?P<method>spf|dkim|dmarc)\s*=\s*"
        r"(?P<result>[a-zA-Z_-]+)"
        r"(?:\s*\((?P<details>[^)]*)\))?"
        r"(?P<params>(?:\s+[a-zA-Z][\w.-]*=[^;\s]+)*)",
        re.IGNORECASE,
    )

    _DOMAIN_PATTERN = re.compile(
        r"(?:^|\s)"
        r"(?P<key>"
        r"smtp\.mailfrom|"
        r"header\.d|"
        r"header\.from|"
        r"envelope\.from|"
        r"envelope\.sender|"
        r"from|"
        r"sender|"
        r"d"
        r")"
        r"\s*=\s*"
        r"(?P<domain>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        re.IGNORECASE,
    )

    _PREFERRED_DOMAIN_KEYS: dict[str, tuple[str, ...]] = {
        "spf": (
            "smtp.mailfrom",
            "envelope.from",
            "envelope.sender",
            "from",
            "sender",
            "d",
        ),
        "dkim": (
            "header.d",
            "d",
        ),
        "dmarc": (
            "header.from",
            "from",
        ),
    }

    def analyze(
        self,
        authentication_results: str | None,
    ) -> AuthenticationResult:
        """Analyze authentication evidence."""

        if not authentication_results:
            return AuthenticationResult(
                spf=None,
                dkim=None,
                dmarc=None,
                spf_domain=None,
                dkim_domain=None,
                dmarc_domain=None,
                passed=False,
                failed=False,
                missing=True,
                findings=[
                    "Authentication-Results header is absent."
                ],
                indicators=[
                    "authentication_results_missing"
                ],
            )

        results: dict[str, str] = {}
        domains: dict[str, str | None] = {
            "spf": None,
            "dkim": None,
            "dmarc": None,
        }

        for match in self._RESULT_PATTERN.finditer(
            authentication_results
        ):
            method = match.group("method").lower()
            result = match.group("result").lower()

            if method not in results:
                results[method] = result

            params = match.group("params") or ""

            domains[method] = self._extract_domain(
                method=method,
                params=params,
            )

        findings: list[str] = []
        indicators: list[str] = []

        for method in ("spf", "dkim", "dmarc"):
            result = results.get(method)

            if result == "pass":
                findings.append(
                    f"{method.upper()} authentication passed."
                )

            elif result == "fail":
                findings.append(
                    f"{method.upper()} authentication failed."
                )
                indicators.append(
                    f"{method}_fail"
                )

            elif result in {
                "softfail",
                "neutral",
                "none",
                "temperror",
                "permerror",
            }:
                findings.append(
                    f"{method.upper()} authentication result: "
                    f"{result}."
                )
                indicators.append(
                    f"{method}_{result}"
                )

            if result and domains[method]:
                findings.append(
                    f"{method.upper()} authenticated domain observed: "
                    f"{domains[method]}."
                )

        if not results:
            findings.append(
                "No SPF, DKIM, or DMARC result could be parsed."
            )
            indicators.append(
                "authentication_methods_unparsed"
            )

        for method in results:
            if domains[method] is None:
                indicators.append(
                    f"{method}_domain_missing"
                )

        passed = any(
            result == "pass"
            for result in results.values()
        )

        failed = any(
            result == "fail"
            for result in results.values()
        )

        return AuthenticationResult(
            spf=results.get("spf"),
            dkim=results.get("dkim"),
            dmarc=results.get("dmarc"),
            spf_domain=domains["spf"],
            dkim_domain=domains["dkim"],
            dmarc_domain=domains["dmarc"],
            passed=passed,
            failed=failed,
            missing=False,
            findings=findings,
            indicators=list(dict.fromkeys(indicators)),
        )

    @classmethod
    def _extract_domain(
        cls,
        *,
        method: str,
        params: str,
    ) -> str | None:
        """
        Extract the domain associated with one authentication method.

        SPF normally uses smtp.mailfrom.
        DKIM normally uses header.d.
        DMARC normally uses header.from.

        Generic fallbacks are supported for less-standard
        Authentication-Results formatting.
        """

        matches = list(
            cls._DOMAIN_PATTERN.finditer(params)
        )

        if not matches:
            return None

        preferred_keys = cls._PREFERRED_DOMAIN_KEYS.get(
            method,
            (),
        )

        for preferred_key in preferred_keys:
            for match in matches:
                key = match.group("key").lower()

                if key == preferred_key:
                    return match.group("domain").lower().rstrip(".")

        return matches[0].group("domain").lower().rstrip(".")


__all__ = [
    "AuthenticationAnalyzer",
    "AuthenticationResult",
]
