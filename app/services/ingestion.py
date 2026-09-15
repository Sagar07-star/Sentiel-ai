
"""
Sentinel AI
Secure Email Evidence Ingestion

Acquires email evidence, preserves the original bytes, records the
forensic hash, creates the investigation record, and records the
initial chain-of-custody events.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import settings
from app.security.evidence import create_evidence_metadata
from app.services.chain_of_custody import (
    ChainOfCustodyError,
    record_acquisition_events,
)
from app.services.evidence_store import EvidenceStore
from app.services.models import Investigation, InvestigationStatus


class IngestionError(Exception):
    """Raised when secure evidence acquisition fails."""


def _validate_filename(filename: str) -> str:
    """Validate and normalize an uploaded filename."""

    cleaned = Path(filename).name.strip()

    if not cleaned:
        raise IngestionError(
            "A valid evidence filename is required."
        )

    if len(cleaned) > 500:
        raise IngestionError(
            "Evidence filename is too long."
        )

    return cleaned


def _validate_media_type(media_type: str) -> str:
    """Validate the supplied media type."""

    cleaned = media_type.strip().lower()

    if not cleaned:
        raise IngestionError(
            "Evidence media type is required."
        )

    return cleaned


def ingest_email(
    *,
    db: Session,
    data: bytes,
    filename: str,
    media_type: str,
) -> Investigation:
    """
    Acquire and preserve an email as forensic evidence.

    Processing order:
    1. Validate raw bytes.
    2. Enforce upload limits.
    3. Calculate forensic metadata.
    4. Persist original evidence bytes.
    5. Verify the stored SHA-256 digest.
    6. Create the investigation record.
    7. Record acquisition custody events.
    8. Commit the database transaction.

    The evidence is never executed or modified.
    """

    if not isinstance(data, bytes):
        raise IngestionError(
            "Evidence must be supplied as raw bytes."
        )

    if not data:
        raise IngestionError(
            "Cannot ingest empty evidence."
        )

    if len(data) > settings.max_email_size_bytes:
        raise IngestionError(
            "Email exceeds the configured maximum size of "
            f"{settings.max_email_size_mb} MB."
        )

    safe_filename = _validate_filename(filename)
    safe_media_type = _validate_media_type(media_type)

    evidence_metadata = create_evidence_metadata(
        data=data,
        filename=safe_filename,
        media_type=safe_media_type,
        analysis_version=settings.app_version,
    )

    evidence_store = EvidenceStore()

    try:
        stored_hash, _evidence_path = evidence_store.store(data)

        if stored_hash != evidence_metadata.sha256:
            raise IngestionError(
                "Stored evidence hash does not match acquisition hash."
            )

        if not evidence_store.verify(
            evidence_metadata.sha256
        ):
            raise IngestionError(
                "Stored evidence failed SHA-256 verification."
            )

        investigation = Investigation(
            investigation_id=(
                f"CASE-{uuid.uuid4().hex[:12].upper()}"
            ),
            evidence_id=evidence_metadata.evidence_id,
            original_filename=evidence_metadata.original_filename,
            media_type=evidence_metadata.media_type,
            evidence_size_bytes=evidence_metadata.size_bytes,
            evidence_sha256=evidence_metadata.sha256,
            status=InvestigationStatus.CREATED.value,
        )

        db.add(investigation)
        db.flush()

        record_acquisition_events(
            db=db,
            investigation_id=investigation.investigation_id,
            evidence_sha256=investigation.evidence_sha256,
        )

        db.commit()
        db.refresh(investigation)

        return investigation

    except (
        IngestionError,
        ChainOfCustodyError,
    ):
        db.rollback()
        raise

    except Exception as exc:
        db.rollback()
        raise IngestionError(
            "Secure evidence ingestion failed."
        ) from exc


__all__ = [
    "IngestionError",
    "ingest_email",
]

