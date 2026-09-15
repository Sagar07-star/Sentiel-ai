from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.security.evidence import calculate_sha256
from app.services.database import Base
from app.services.ingestion import IngestionError, ingest_email
from app.services.models import InvestigationStatus


@pytest.fixture()
def db(tmp_path: Path) -> Session:
    """Create an isolated test database."""
    database_path = tmp_path / "test.db"

    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)

    with Session(engine) as session:
        yield session


def test_ingest_email_preserves_forensic_hash(
    db: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ingestion should preserve the exact evidence hash."""
    monkeypatch.chdir(tmp_path)

    email_data = (
        b"From: sender@example.com\r\n"
        b"To: analyst@example.com\r\n"
        b"Subject: Test message\r\n"
        b"\r\n"
        b"This is forensic test evidence."
    )

    investigation = ingest_email(
        db=db,
        data=email_data,
        filename="sample.eml",
        media_type="message/rfc822",
    )

    assert investigation.investigation_id.startswith("CASE-")
    assert investigation.evidence_id
    assert investigation.evidence_sha256 == calculate_sha256(email_data)
    assert investigation.evidence_size_bytes == len(email_data)
    assert investigation.status == InvestigationStatus.CREATED.value

    evidence_path = (
        tmp_path
        / "runtime"
        / "evidence"
        / f"{investigation.evidence_sha256}.eml"
    )

    assert evidence_path.exists()
    assert evidence_path.read_bytes() == email_data


def test_ingest_rejects_empty_evidence(db: Session) -> None:
    """Empty uploads must never enter the forensic pipeline."""
    with pytest.raises(IngestionError):
        ingest_email(
            db=db,
            data=b"",
            filename="empty.eml",
            media_type="message/rfc822",
        )


def test_ingest_rejects_invalid_filename(db: Session) -> None:
    """Invalid filenames must be rejected."""
    with pytest.raises(IngestionError):
        ingest_email(
            db=db,
            data=b"test evidence",
            filename="",
            media_type="message/rfc822",
        )


def test_ingest_rejects_invalid_media_type(db: Session) -> None:
    """Missing media types must be rejected."""
    with pytest.raises(IngestionError):
        ingest_email(
            db=db,
            data=b"test evidence",
            filename="sample.eml",
            media_type="",
        )


def test_ingest_strips_path_from_filename(
    db: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """User-controlled paths must never control evidence storage."""
    monkeypatch.chdir(tmp_path)

    investigation = ingest_email(
        db=db,
        data=b"safe evidence",
        filename=r"..\..\malicious\sample.eml",
        media_type="message/rfc822",
    )

    assert investigation.original_filename == "sample.eml"

    evidence_path = (
        tmp_path
        / "runtime"
        / "evidence"
        / f"{investigation.evidence_sha256}.eml"
    )

    assert evidence_path.exists()