"""
Sentinel AI
Forensic Evidence Domain Models

Structured models used throughout the investigation pipeline.

These models intentionally separate:
- acquired evidence
- extracted artifacts
- analytical observations
- confidence
- provenance

A detector should never silently turn an observation into a fact.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvidenceType(StrEnum):
    """High-level evidence categories."""

    EMAIL = "email"
    HEADER = "header"
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    ATTACHMENT = "attachment"
    DNS = "dns"
    AUTHENTICATION = "authentication"
    IDENTITY = "identity"
    BEHAVIOR = "behavior"
    INFRASTRUCTURE = "infrastructure"


class ConfidenceLevel(StrEnum):
    """Human-readable confidence levels."""

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class ObservationStatus(StrEnum):
    """Status of an analytical observation."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    CORRELATED = "correlated"
    UNKNOWN = "unknown"


class EvidenceReference(BaseModel):
    """Reference to a specific piece of evidence."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1)
    evidence_type: EvidenceType
    label: str = Field(min_length=1, max_length=500)
    value: str = Field(default="", max_length=2000)


class EvidenceObservation(BaseModel):
    """
    A single analytical observation.

    Observations describe what Sentinel found. They do not claim
    attribution or intent unless supported by additional evidence.
    """

    model_config = ConfigDict(extra="forbid")

    observation_id: str = Field(min_length=1)
    evidence_type: EvidenceType
    title: str = Field(min_length=1, max_length=300)
    description: str = Field(min_length=1, max_length=5000)

    status: ObservationStatus = ObservationStatus.OBSERVED
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel = ConfidenceLevel.MEDIUM

    evidence: list[EvidenceReference] = Field(default_factory=list)

    analyzer: str = Field(min_length=1, max_length=200)
    analyzer_version: str = Field(min_length=1, max_length=100)

    created_at: datetime


class Artifact(BaseModel):
    """
    Normalized artifact extracted from evidence.

    Examples:
    - URL
    - domain
    - IP address
    - email address
    - attachment
    """

    model_config = ConfigDict(extra="forbid")

    artifact_id: str = Field(min_length=1)
    artifact_type: EvidenceType

    value: str = Field(min_length=1, max_length=2000)

    normalized_value: str = Field(
        min_length=1,
        max_length=2000,
    )

    source_evidence_id: str = Field(min_length=1)

    first_seen: datetime
    last_seen: datetime

    metadata: dict[str, Any] = Field(default_factory=dict)


class ChainOfCustodyEvent(BaseModel):
    """Auditable event describing handling of evidence."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)

    action: str = Field(min_length=1, max_length=200)

    timestamp: datetime

    actor: str = Field(
        default="sentinel-system",
        min_length=1,
        max_length=200,
    )

    details: str = Field(
        default="",
        max_length=5000,
    )

    evidence_hash: str | None = Field(
        default=None,
        min_length=64,
        max_length=64,
    )


class EvidenceBundle(BaseModel):
    """
    Complete logical collection of evidence and observations
    associated with an investigation.
    """

    model_config = ConfigDict(extra="forbid")

    investigation_id: str = Field(min_length=1)

    primary_evidence: EvidenceReference

    artifacts: list[Artifact] = Field(default_factory=list)

    observations: list[EvidenceObservation] = Field(
        default_factory=list,
    )

    chain_of_custody: list[ChainOfCustodyEvent] = Field(
        default_factory=list,
    )

    created_at: datetime
    updated_at: datetime