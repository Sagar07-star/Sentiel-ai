"""
Sentinel AI
Infrastructure Intelligence

Performs passive infrastructure enrichment.

Important:
Geolocation represents the location of the observed infrastructure/IP.
It does NOT establish the physical location or identity of an attacker.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

import httpx


class InfrastructureAnalyzer:
    """Enrich observed domains and IP addresses with infrastructure data."""

    def __init__(self) -> None:
        self.timeout = 3.0

    def analyze(
        self,
        *,
        domains: list[str],
        ip_addresses: list[str],
    ) -> list[dict[str, object]]:
        """Build infrastructure records without executing remote content."""

        resolved_ips = list(ip_addresses)

        for domain in domains:
            resolved_ips.extend(self._resolve_domain(domain))

        unique_ips = list(dict.fromkeys(resolved_ips))

        results: list[dict[str, object]] = []

        for ip in unique_ips:
            record = self._analyze_ip(ip)

            if record:
                results.append(record)

        return results

    def _analyze_ip(self, ip: str) -> dict[str, object] | None:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return None

        record: dict[str, object] = {
            "ip": str(parsed),
            "version": parsed.version,
            "is_private": parsed.is_private,
            "is_global": parsed.is_global,
            "is_reserved": parsed.is_reserved,
            "geolocation": None,
        }

        if not parsed.is_global:
            return record

        geo = self._lookup_geolocation(str(parsed))

        if geo:
            record["geolocation"] = geo

        return record

    @staticmethod
    def _resolve_domain(domain: str) -> list[str]:
        """Resolve a domain to observed IP addresses using the local resolver."""

        try:
            results = socket.getaddrinfo(
                domain,
                None,
                type=socket.SOCK_STREAM,
            )
        except (OSError, socket.gaierror):
            return []

        addresses: list[str] = []

        for result in results:
            address = str(result[4][0])

            if address:
                addresses.append(address)

        return list(dict.fromkeys(addresses))

    def _lookup_geolocation(
        self,
        ip: str,
    ) -> dict[str, Any] | None:
        """
        Query an HTTPS IP geolocation service.

        The result is enrichment only. It is not attribution evidence.
        """

        url = f"https://ipwho.is/{ip}"

        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=False,
            ) as client:
                response = client.get(url)

            if response.status_code != 200:
                return None

            payload = response.json()

        except (
            httpx.HTTPError,
            ValueError,
            TypeError,
        ):
            return None

        if not isinstance(payload, dict):
            return None

        if payload.get("success") is False:
            return None

        connection = payload.get("connection", {})

        if not isinstance(connection, dict):
            connection = {}

        return {
            "country": payload.get("country"),
            "country_code": payload.get("country_code"),
            "region": payload.get("region"),
            "city": payload.get("city"),
            "latitude": payload.get("latitude"),
            "longitude": payload.get("longitude"),
            "timezone": payload.get("timezone"),
            "isp": connection.get("isp"),
            "organization": connection.get("org"),
            "asn": connection.get("asn"),
            "source": "ipwho.is",
            "classification": "infrastructure_geolocation",
        }


__all__ = [
    "InfrastructureAnalyzer",
]