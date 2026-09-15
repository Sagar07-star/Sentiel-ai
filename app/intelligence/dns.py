"""
Sentinel AI
DNS Infrastructure Intelligence

Resolves observable DNS information for investigation purposes.

This module does not claim that infrastructure location equals
attacker physical location.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DNSResult:
    domain: str
    addresses: list[str]
    canonical_name: str | None
    resolved: bool
    findings: list[str]


class DNSIntelligence:
    """Perform bounded local DNS resolution."""

    def resolve(self, domain: str) -> DNSResult:
        normalized = domain.strip().lower().rstrip(".")

        if not normalized:
            return DNSResult(
                domain=domain,
                addresses=[],
                canonical_name=None,
                resolved=False,
                findings=["Domain is empty."],
            )

        try:
            socket.inet_aton(normalized)
            return DNSResult(
                domain=normalized,
                addresses=[normalized],
                canonical_name=None,
                resolved=True,
                findings=["Input is already an IPv4 address."],
            )
        except OSError:
            pass

        try:
            host_info = socket.gethostbyname_ex(normalized)

            addresses = self._valid_addresses(host_info[2])

            if not addresses:
                return DNSResult(
                    domain=normalized,
                    addresses=[],
                    canonical_name=host_info[0] or None,
                    resolved=False,
                    findings=["DNS returned no valid IPv4 addresses."],
                )

            return DNSResult(
                domain=normalized,
                addresses=addresses,
                canonical_name=host_info[0] or None,
                resolved=True,
                findings=[
                    f"Domain resolved to {len(addresses)} IPv4 address(es)."
                ],
            )

        except (socket.gaierror, OSError):
            return DNSResult(
                domain=normalized,
                addresses=[],
                canonical_name=None,
                resolved=False,
                findings=["Domain could not be resolved."],
            )

    @staticmethod
    def _valid_addresses(addresses: list[str]) -> list[str]:
        valid: list[str] = []

        for address in addresses:
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue

            if address not in valid:
                valid.append(address)

        return valid


__all__ = [
    "DNSIntelligence",
    "DNSResult",
]