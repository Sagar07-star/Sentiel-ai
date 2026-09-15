
"""
Sentinel AI
Persistent Chain of Custody

Provides append-only forensic custody events for investigations.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.services.models import ChainOfCustodyEvent, CustodyEventType


class ChainOfCustodyError(Exception):
    """Raised when a custody event cannot be recorded."""


def record_custody_event(
    *,
    db: Session,
    investigation_id: str,
    evidence_sha256: str,
    event_type: CustodyEventType,
    description: str,
    actor: str = "sentinel-ai",
) -> ChainOfCustodyEvent:
    """Append one forensic custody event."""

    normalized_investigation_id = investigation_id.strip()
    normalized_hash = evidence_sha256.strip().lower()
    normalized_actor = actor.strip() or "sentinel-ai"
    normalized_description = description.strip()

    if not normalized_investigation_id:
        raise ChainOfCustodyError(
            "Investigation ID is required."
        )

    if len(normalized_hash) != 64:
        raise ChainOfCustodyError(
            "A valid SHA-256 digest is required."
        )

    if any(
        character not in "0123456789abcdef"
        for character in normalized_hash
    ):
        raise ChainOfCustodyError(
            "A valid SHA-256 digest is required."
        )

    if not normalized_description:
        raise ChainOfCustodyError(
            "Custody event description is required."
        )

    event = ChainOfCustodyEvent(
        investigation_id=normalized_investigation_id,
        event_type=event_type.value,
        evidence_sha256=normalized_hash,
        timestamp=datetime.now(UTC),
        actor=normalized_actor,
        description=normalized_description,
    )

    db.add(event)

    try:
        db.flush()
    except Exception as exc:
        raise ChainOfCustodyError(
            "Unable to record chain-of-custody event."
        ) from exc

    return event


def record_acquisition_events(
    *,
    db: Session,
    investigation_id: str,
    evidence_sha256: str,
) -> list[ChainOfCustodyEvent]:
    """Record the initial acquisition and preservation events."""

    events = [
        record_custody_event(
            db=db,
            investigation_id=investigation_id,
            evidence_sha256=evidence_sha256,
            event_type=CustodyEventType.ACQUIRED,
            description=(
                "Email evidence was acquired as immutable forensic input."
            ),
        ),
        record_custody_event(
            db=db,
            investigation_id=investigation_id,
            evidence_sha256=evidence_sha256,
            event_type=CustodyEventType.HASH_VERIFIED,
            description=(
                "SHA-256 digest was verified against the acquired evidence."
            ),
        ),
        record_custody_event(
            db=db,
            investigation_id=investigation_id,
            evidence_sha256=evidence_sha256,
            event_type=CustodyEventType.STORED,
            description=(
                "Original evidence bytes were persisted in the "
                "content-addressed evidence store."
            ),
        ),
    ]

    return events


__all__ = [
    "ChainOfCustodyError",
    "record_acquisition_events",
    "record_custody_event",
]
