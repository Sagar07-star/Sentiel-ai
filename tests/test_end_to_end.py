from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.security.evidence import calculate_sha256, verify_evidence_integrity
from app.services.analysis_pipeline import AnalysisPipeline
from app.services.database import Base
from app.services.ingestion import ingest_email


@pytest.fixture()
def db(tmp_path: Path) -> Session:
    database_path = tmp_path / "sentinel_test.db"

    engine = create_engine(
        f"sqlite:///{database_path}",
        connect_args={"check_same_thread": False},
    )

    Base.metadata.create_all(engine)

    with Session(engine) as session:
        yield session


def test_full_forensic_workflow(
    db: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    email = (
        b"From: security@example.com\r\n"
        b"To: analyst@example.com\r\n"
        b"Reply-To: attacker@evil.example\r\n"
        b"Subject: URGENT account verification\r\n"
        b"Date: Thu, 03 Sep 2026 12:00:00 +0000\r\n"
        b"Authentication-Results: mx.example.com; "
        b"spf=fail smtp.mailfrom=evil.example; "
        b"dmarc=fail header.from=example.com\r\n"
        b"\r\n"
        b"Verify your account immediately. "
        b"Visit http://192.168.1.10/login "
        b"and enter your password."
    )

    expected_hash = calculate_sha256(email)

    investigation = ingest_email(
        db=db,
        data=email,
        filename="evidence.eml",
        media_type="message/rfc822",
    )

    assert investigation.evidence_sha256 == expected_hash
    assert investigation.status == "created"

    evidence_path = (
        tmp_path
        / "runtime"
        / "evidence"
        / f"{expected_hash}.eml"
    )

    assert evidence_path.exists()
    assert evidence_path.read_bytes() == email

    assert verify_evidence_integrity(
        data=evidence_path.read_bytes(),
        expected_sha256=expected_hash,
    )

    result = AnalysisPipeline().analyze(email)

    assert result.risk.score > 0
    assert result.risk.verdict in {
        "low",
        "medium",
        "high",
        "critical",
    }

    assert result.indicators
    assert result.urls
    assert result.ip_addresses

    # This test email contains an IP-based URL and no domain URL.
    assert result.domains == []

    assert result.correlated_findings
    assert result.counterfactual.scenarios
    assert result.timeline


def test_tampered_evidence_is_detected(
    db: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    email = b"From: test@example.com\r\n\r\nOriginal evidence."

    investigation = ingest_email(
        db=db,
        data=email,
        filename="sample.eml",
        media_type="message/rfc822",
    )

    evidence_path = (
        tmp_path
        / "runtime"
        / "evidence"
        / f"{investigation.evidence_sha256}.eml"
    )

    evidence_path.write_bytes(
        b"From: test@example.com\r\n\r\nTAMPERED evidence."
    )

    tampered_data = evidence_path.read_bytes()

    assert not verify_evidence_integrity(
        data=tampered_data,
        expected_sha256=investigation.evidence_sha256,
    )