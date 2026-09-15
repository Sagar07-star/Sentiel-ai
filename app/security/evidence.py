"""
Sentinel AI
Forensic Evidence Integrity

Creates deterministic forensic metadata for acquired evidence.

Security principles:
- Original evidence bytes are never modified.
- SHA-256 is calculated over the exact acquired bytes.
- Evidence metadata is immutable.
- Acquisition metadata is separated from analytical conclusions.
- Uploaded content is never executed.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class EvidenceMetadata:
    """Immutable metadata describing acquired evidence."""

    evidence_id: str
    original_filename: str
    size_bytes: int
    sha256: str
    acquired_at: datetime
    media_type: str
    analysis_version: str


def calculate_sha256(data: bytes) -> str:
    """
    Calculate SHA-256 over the exact evidence bytes.

    No normalization, decoding, or transformation is performed.
    """
    if not isinstance(data, bytes):
        raise TypeError("Evidence data must be bytes.")

    return hashlib.sha256(data).hexdigest()


def create_evidence_metadata(
    *,
    data: bytes,
    filename: str,
    media_type: str,
    analysis_version: str,
) -> EvidenceMetadata:
    """
    Create immutable forensic metadata for acquired evidence.
    """
    if not isinstance(data, bytes):
        raise TypeError("Evidence data must be bytes.")

    if not filename.strip():
        raise ValueError("Evidence filename cannot be empty.")

    if not media_type.strip():
        raise ValueError("Evidence media type cannot be empty.")

    if not analysis_version.strip():
        raise ValueError("Analysis version cannot be empty.")

    return EvidenceMetadata(
        evidence_id=str(uuid.uuid4()),
        original_filename=filename,
        size_bytes=len(data),
        sha256=calculate_sha256(data),
        acquired_at=datetime.now(UTC),
        media_type=media_type,
        analysis_version=analysis_version,
    )


def verify_evidence_integrity(
    *,
    data: bytes,
    expected_sha256: str,
) -> bool:
    """
    Verify that evidence bytes match the recorded SHA-256 digest.
    """
    if not isinstance(data, bytes):
        raise TypeError("Evidence data must be bytes.")

    normalized_expected = expected_sha256.strip().lower()

    if len(normalized_expected) != 64:
        return False

    if any(
        character not in "0123456789abcdef"
        for character in normalized_expected
    ):
        return False

    actual_sha256 = calculate_sha256(data)

    return hmac.compare_digest(
        actual_sha256,
        normalized_expected,
    )


__all__ = [
    "EvidenceMetadata",
    "calculate_sha256",
    "create_evidence_metadata",
    "verify_evidence_integrity",
]