"""
Sentinel AI
IP Infrastructure Intelligence

Provides a provider-neutral model for IP geolocation and ASN data.

The core system does not invent geolocation. Real location data is
supplied by an external intelligence provider when configured.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class IPIntelligence:
    ip_address: str
    valid: bool
    is_private: bool
    country: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    asn: str | None
    organization: str | None
    network_type: str | None
    source: str
    findings: list[str]


class IPAnalyzer:
    """Validate IP addresses and normalize intelligence results."""

    def analyze(
        self,
        ip_address: str,
        *,
        country: str | None = None,
        region: str | None = None,
        city: str | None = None,
        latitude: float | None = None,
        longitude: float | None = None,
        asn: str | None = None,
        organization: str | None = None,
        network_type: str | None = None,
        source: str = "unavailable",
    ) -> IPIntelligence:
        normalized = ip_address.strip()

        try:
            address = ipaddress.ip_address(normalized)
        except ValueError:
            return IPIntelligence(
                ip_address=normalized,
                valid=False,
                is_private=False,
                country=None,
                region=None,
                city=None,
                latitude=None,
                longitude=None,
                asn=None,
                organization=None,
                network_type=None,
                source="validation",
                findings=["Invalid IP address."],
            )

        findings: list[str] = []

        if address.is_private:
            findings.append(
                "IP address belongs to private address space."
            )

        if address.is_loopback:
            findings.append(
                "IP address is a loopback address."
            )

        if address.is_reserved:
            findings.append(
                "IP address belongs to reserved address space."
            )

        if source == "unavailable":
            findings.append(
                "No external geolocation provider was available."
            )

        if country or city or asn or organization:
            findings.append(
                "Geolocation describes network infrastructure, "
                "not attacker physical location."
            )

        return IPIntelligence(
            ip_address=str(address),
            valid=True,
            is_private=address.is_private,
            country=country,
            region=region,
            city=city,
            latitude=latitude,
            longitude=longitude,
            asn=asn,
            organization=organization,
            network_type=network_type,
            source=source,
            findings=findings,
        )


__all__ = [
    "IPAnalyzer",
    "IPIntelligence",
]