"""
Sentinel AI
Indicator Extraction

Extracts observable URLs, domains, and IP addresses from email content.
No network requests are made by this module.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True, slots=True)
class ExtractedIndicators:
    urls: list[str]
    domains: list[str]
    ip_addresses: list[str]


class IndicatorExtractor:
    """Extract network indicators without contacting them."""

    URL_PATTERN = re.compile(
        r"https?://[^\s<>'\"()]+",
        re.IGNORECASE,
    )

    DOMAIN_PATTERN = re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}\b"
    )

    IP_PATTERN = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )

    def extract(
        self,
        *,
        plain_text: str = "",
        html: str = "",
    ) -> ExtractedIndicators:
        content = f"{plain_text}\n{html}"

        urls = self._extract_urls(content)
        domains = self._extract_domains(content, urls)
        ip_addresses = self._extract_ips(content)

        return ExtractedIndicators(
            urls=urls,
            domains=domains,
            ip_addresses=ip_addresses,
        )

    def _extract_urls(self, content: str) -> list[str]:
        found: list[str] = []

        for match in self.URL_PATTERN.finditer(content):
            url = match.group(0).rstrip(".,;:!?)]}")
            if self._valid_url(url):
                found.append(url)

        return self._unique(found)

    def _extract_domains(
        self,
        content: str,
        urls: list[str],
    ) -> list[str]:
        domains: list[str] = []

        for url in urls:
            try:
                hostname = urlparse(url).hostname
            except ValueError:
                hostname = None

            if hostname:
                hostname = hostname.lower().rstrip(".")
                if not self._is_ip(hostname):
                    domains.append(hostname)

        for match in self.DOMAIN_PATTERN.finditer(content):
            domain = match.group(0).lower().rstrip(".")
            if not self._is_ip(domain):
                domains.append(domain)

        return self._unique(domains)

    def _extract_ips(self, content: str) -> list[str]:
        ips: list[str] = []

        for match in self.IP_PATTERN.finditer(content):
            candidate = match.group(0)

            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue

            ips.append(candidate)

        return self._unique(ips)

    @staticmethod
    def _valid_url(url: str) -> bool:
        try:
            parsed = urlparse(url)
        except ValueError:
            return False

        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
        )

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []

        for value in values:
            if value not in seen:
                seen.add(value)
                result.append(value)

        return result


__all__ = [
    "ExtractedIndicators",
    "IndicatorExtractor",
]