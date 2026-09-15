"""
Sentinel AI
Forensic Attack Graph

Builds an explainable graph connecting observable email evidence
into an investigation path.

The graph represents evidence relationships only.
It does not claim attacker identity, physical location, or attribution.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AttackGraphNode:
    """One observable entity in the forensic graph."""

    node_id: str
    node_type: str
    label: str
    evidence: list[str]


@dataclass(frozen=True, slots=True)
class AttackGraphEdge:
    """Relationship between two forensic graph nodes."""

    source: str
    target: str
    relationship: str
    evidence: list[str]


@dataclass(frozen=True, slots=True)
class AttackGraph:
    """Complete forensic attack graph."""

    nodes: list[AttackGraphNode]
    edges: list[AttackGraphEdge]


class AttackGraphBuilder:
    """Build an attack graph from pipeline evidence."""

    def build(
        self,
        *,
        sender: str | None = None,
        reply_to: str | None = None,
        return_path: str | None = None,
        domains: list[str] | None = None,
        urls: list[str] | None = None,
        ip_addresses: list[str] | None = None,
        indicators: list[str] | None = None,
        attachment_findings: list[str] | None = None,
        behavioral_findings: list[str] | None = None,
    ) -> AttackGraph:
        """Construct a deterministic evidence relationship graph."""

        nodes: list[AttackGraphNode] = []
        edges: list[AttackGraphEdge] = []

        unique_indicators = list(
            dict.fromkeys(indicators or [])
        )

        unique_domains = list(
            dict.fromkeys(domains or [])
        )

        unique_urls = list(
            dict.fromkeys(urls or [])
        )

        unique_ips = list(
            dict.fromkeys(ip_addresses or [])
        )

        sender_node: str | None = None

        if sender:
            sender_node = self._add_node(
                nodes,
                node_type="identity",
                label=sender,
                evidence=[
                    "visible_sender",
                ],
            )

        if reply_to:
            reply_node = self._add_node(
                nodes,
                node_type="identity",
                label=reply_to,
                evidence=[
                    "reply_to",
                ],
            )

            if sender_node:
                relationship = (
                    "reply_to_mismatch"
                    if "reply_to_domain_mismatch" in unique_indicators
                    else "reply_to"
                )

                evidence = (
                    ["reply_to_domain_mismatch"]
                    if relationship == "reply_to_mismatch"
                    else ["reply_to"]
                )

                edges.append(
                    AttackGraphEdge(
                        source=sender_node,
                        target=reply_node,
                        relationship=relationship,
                        evidence=evidence,
                    )
                )

        if return_path:
            return_node = self._add_node(
                nodes,
                node_type="identity",
                label=return_path,
                evidence=[
                    "return_path",
                ],
            )

            if sender_node:
                relationship = (
                    "return_path_mismatch"
                    if "return_path_domain_mismatch" in unique_indicators
                    else "return_path"
                )

                evidence = (
                    ["return_path_domain_mismatch"]
                    if relationship == "return_path_mismatch"
                    else ["return_path"]
                )

                edges.append(
                    AttackGraphEdge(
                        source=sender_node,
                        target=return_node,
                        relationship=relationship,
                        evidence=evidence,
                    )
                )

        domain_nodes: dict[str, str] = {}

        for domain in unique_domains:
            node_id = self._add_node(
                nodes,
                node_type="domain",
                label=domain,
                evidence=[
                    "extracted_domain",
                ],
            )

            domain_nodes[domain] = node_id

            if sender_node:
                edges.append(
                    AttackGraphEdge(
                        source=sender_node,
                        target=node_id,
                        relationship="references_domain",
                        evidence=[
                            "email_indicator_extraction",
                        ],
                    )
                )

        for url in unique_urls:
            url_node = self._add_node(
                nodes,
                node_type="url",
                label=url,
                evidence=[
                    "extracted_url",
                ],
            )

            matching_domain = self._match_domain(
                url,
                unique_domains,
            )

            if matching_domain:
                edges.append(
                    AttackGraphEdge(
                        source=url_node,
                        target=domain_nodes[matching_domain],
                        relationship="resolves_to_domain",
                        evidence=[
                            "url_domain_relationship",
                        ],
                    )
                )

            if sender_node:
                edges.append(
                    AttackGraphEdge(
                        source=sender_node,
                        target=url_node,
                        relationship="contains_link",
                        evidence=[
                            "email_indicator_extraction",
                        ],
                    )
                )

        for ip_address in unique_ips:
            ip_node = self._add_node(
                nodes,
                node_type="ip",
                label=ip_address,
                evidence=[
                    "observed_ip",
                ],
            )

            for domain, domain_node in domain_nodes.items():
                if ip_address == domain:
                    edges.append(
                        AttackGraphEdge(
                            source=domain_node,
                            target=ip_node,
                            relationship="maps_to_ip",
                            evidence=[
                                "infrastructure_observation",
                            ],
                        )
                    )

            if any(
                indicator == "ip_based_url"
                for indicator in unique_indicators
            ):
                edges.append(
                    AttackGraphEdge(
                        source=ip_node,
                        target=ip_node,
                        relationship="ip_based_destination",
                        evidence=[
                            "ip_based_url",
                        ],
                    )
                )

        if attachment_findings:
            attachment_node = self._add_node(
                nodes,
                node_type="attachment",
                label="Suspicious attachment",
                evidence=list(
                    dict.fromkeys(attachment_findings)
                ),
            )

            if sender_node:
                edges.append(
                    AttackGraphEdge(
                        source=sender_node,
                        target=attachment_node,
                        relationship="delivers_attachment",
                        evidence=list(
                            dict.fromkeys(attachment_findings)
                        ),
                    )
                )

        if behavioral_findings:
            behavior_node = self._add_node(
                nodes,
                node_type="behavior",
                label="Social engineering behavior",
                evidence=list(
                    dict.fromkeys(behavioral_findings)
                ),
            )

            if sender_node:
                edges.append(
                    AttackGraphEdge(
                        source=sender_node,
                        target=behavior_node,
                        relationship="uses_social_engineering",
                        evidence=list(
                            dict.fromkeys(behavioral_findings)
                        ),
                    )
                )

        if unique_indicators:
            evidence_node = self._add_node(
                nodes,
                node_type="evidence",
                label="Correlated threat indicators",
                evidence=unique_indicators,
            )

            if sender_node:
                edges.append(
                    AttackGraphEdge(
                        source=sender_node,
                        target=evidence_node,
                        relationship="supported_by",
                        evidence=unique_indicators,
                    )
                )

        return AttackGraph(
            nodes=self._deduplicate_nodes(nodes),
            edges=self._deduplicate_edges(edges),
        )

    @staticmethod
    def _add_node(
        nodes: list[AttackGraphNode],
        *,
        node_type: str,
        label: str,
        evidence: list[str],
    ) -> str:
        """Add a node and return its deterministic identifier."""

        node_id = (
            f"{node_type}:"
            f"{label.strip().lower()}"
        )

        nodes.append(
            AttackGraphNode(
                node_id=node_id,
                node_type=node_type,
                label=label,
                evidence=list(
                    dict.fromkeys(evidence)
                ),
            )
        )

        return node_id

    @staticmethod
    def _match_domain(
        url: str,
        domains: list[str],
    ) -> str | None:
        """Find the domain represented by a URL."""

        from urllib.parse import urlparse

        try:
            hostname = urlparse(url).hostname
        except ValueError:
            return None

        if not hostname:
            return None

        normalized_host = hostname.lower().rstrip(".")

        for domain in domains:
            normalized_domain = (
                domain.lower()
                .rstrip(".")
            )

            if (
                normalized_host == normalized_domain
                or normalized_host.endswith(
                    f".{normalized_domain}"
                )
            ):
                return domain

        return None

    @staticmethod
    def _deduplicate_nodes(
        nodes: list[AttackGraphNode],
    ) -> list[AttackGraphNode]:
        """Merge duplicate graph nodes."""

        merged: dict[str, AttackGraphNode] = {}

        for node in nodes:
            existing = merged.get(node.node_id)

            if existing is None:
                merged[node.node_id] = node
                continue

            merged[node.node_id] = AttackGraphNode(
                node_id=node.node_id,
                node_type=node.node_type,
                label=node.label,
                evidence=list(
                    dict.fromkeys(
                        [
                            *existing.evidence,
                            *node.evidence,
                        ]
                    )
                ),
            )

        return list(merged.values())

    @staticmethod
    def _deduplicate_edges(
        edges: list[AttackGraphEdge],
    ) -> list[AttackGraphEdge]:
        """Merge duplicate graph relationships."""

        merged: dict[
            tuple[str, str, str],
            AttackGraphEdge,
        ] = {}

        for edge in edges:
            key = (
                edge.source,
                edge.target,
                edge.relationship,
            )

            existing = merged.get(key)

            if existing is None:
                merged[key] = edge
                continue

            merged[key] = AttackGraphEdge(
                source=edge.source,
                target=edge.target,
                relationship=edge.relationship,
                evidence=list(
                    dict.fromkeys(
                        [
                            *existing.evidence,
                            *edge.evidence,
                        ]
                    )
                ),
            )

        return list(merged.values())


__all__ = [
    "AttackGraph",
    "AttackGraphBuilder",
    "AttackGraphEdge",
    "AttackGraphNode",
]