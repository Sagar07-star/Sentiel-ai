"""
Sentinel AI
Forensic Evidence Store

Secure local evidence storage for development and forensic workflows.

Design principles:
- Evidence is stored using its SHA-256 digest.
- Original bytes are written exactly as acquired.
- Evidence is never executed.
- Existing evidence cannot be silently overwritten.
- Storage paths are derived internally, never from user input.
"""

from __future__ import annotations

from pathlib import Path

from app.config import settings
from app.security.evidence import calculate_sha256


class EvidenceStorageError(Exception):
    """Raised when forensic evidence cannot be safely stored."""


class EvidenceStore:
    """Local immutable evidence store."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or Path("runtime") / "evidence"
        self.root.mkdir(parents=True, exist_ok=True)

    def store(self, data: bytes) -> tuple[str, Path]:
        """
        Store evidence using its SHA-256 digest.

        Returns:
            A tuple containing the SHA-256 digest and storage path.
        """
        if not isinstance(data, bytes):
            raise EvidenceStorageError(
                "Evidence must be supplied as raw bytes."
            )

        if not data:
            raise EvidenceStorageError(
                "Cannot store empty evidence."
            )

        if len(data) > settings.max_email_size_bytes:
            raise EvidenceStorageError(
                "Evidence exceeds the configured maximum size."
            )

        digest = calculate_sha256(data)

        evidence_path = self.root / f"{digest}.eml"

        if evidence_path.exists():
            existing_data = evidence_path.read_bytes()

            if calculate_sha256(existing_data) != digest:
                raise EvidenceStorageError(
                    "Existing evidence failed integrity verification."
                )

            return digest, evidence_path

        temporary_path = self.root / f".{digest}.tmp"

        try:
            temporary_path.write_bytes(data)

            written_data = temporary_path.read_bytes()

            if calculate_sha256(written_data) != digest:
                raise EvidenceStorageError(
                    "Evidence integrity verification failed after writing."
                )

            temporary_path.replace(evidence_path)

        except OSError as exc:
            raise EvidenceStorageError(
                "Unable to persist forensic evidence."
            ) from exc

        finally:
            if temporary_path.exists():
                try:
                    temporary_path.unlink()
                except OSError:
                    pass

        return digest, evidence_path

    def verify(self, digest: str) -> bool:
        """Verify stored evidence against its expected SHA-256 digest."""
        normalized_digest = digest.strip().lower()

        if len(normalized_digest) != 64:
            return False

        if any(
            character not in "0123456789abcdef"
            for character in normalized_digest
        ):
            return False

        evidence_path = self.root / f"{normalized_digest}.eml"

        if not evidence_path.is_file():
            return False

        try:
            stored_data = evidence_path.read_bytes()
        except OSError:
            return False

        return calculate_sha256(stored_data) == normalized_digest

    def get_path(self, digest: str) -> Path:
        """Return the internal storage path for an evidence digest."""
        normalized_digest = digest.strip().lower()

        if len(normalized_digest) != 64:
            raise EvidenceStorageError(
                "Invalid evidence SHA-256 digest."
            )

        if any(
            character not in "0123456789abcdef"
            for character in normalized_digest
        ):
            raise EvidenceStorageError(
                "Invalid evidence SHA-256 digest."
            )

        return self.root / f"{normalized_digest}.eml"


__all__ = [
    "EvidenceStorageError",
    "EvidenceStore",
]