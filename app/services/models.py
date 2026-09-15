"""
Sentinel AI
Database Models

Persistent models for investigations and forensic evidence.

Design principles:
- Database records describe investigations, evidence, analysis, reports,
  and custody events.
- Raw email content is not stored unless explicitly enabled.
- SHA-256 identifies acquired evidence.
- Analysis results are stored as JSON for complete investigation retrieval.
- Custody events provide an auditable investigation history.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.services.database import Base


class InvestigationStatus(StrEnum):
    """Lifecycle state of an investigation."""

    CREATED = "created"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"


class CustodyEventType(StrEnum):
    """Types of forensic chain-of-custody events."""

    ACQUIRED = "acquired"
    HASH_VERIFIED = "hash_verified"
    STORED = "stored"
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYSIS_FAILED = "analysis_failed"
    REPORT_GENERATED = "report_generated"


class Investigation(Base):
    """
    Persistent investigation record.

    One investigation represents one acquired email/evidence item
    and all analysis performed against it.
    """

    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    investigation_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )

    evidence_id: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )

    original_filename: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
    )

    media_type: Mapped[str] = mapped_column(
        String(200),
        nullable=False,
    )

    evidence_size_bytes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    evidence_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        default=InvestigationStatus.CREATED.value,
        nullable=False,
        index=True,
    )

    verdict: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    risk_score: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    confidence: Mapped[float | None] = mapped_column(
        Float,
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    analysis_result: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    forensic_report: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


class ChainOfCustodyEvent(Base):
    """
    Immutable forensic custody event.

    Events are append-only from the application perspective. A custody
    event records what happened to an evidence item, when it happened,
    and which SHA-256 digest was associated with that event.
    """

    __tablename__ = "chain_of_custody_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    investigation_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey(
            "investigations.investigation_id",
            ondelete="CASCADE",
        ),
        index=True,
        nullable=False,
    )

    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    evidence_sha256: Mapped[str] = mapped_column(
        String(64),
        index=True,
        nullable=False,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )

    actor: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="sentinel-ai",
    )

    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )


__all__ = [
    "ChainOfCustodyEvent",
    "CustodyEventType",
    "Investigation",
    "InvestigationStatus",
]