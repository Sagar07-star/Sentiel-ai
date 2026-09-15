"""
Sentinel AI
Investigation API

Secure investigation lifecycle:
- evidence acquisition
- forensic analysis
- audit logging
- chain of custody
- persistent analysis/report storage
- investigation retrieval
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.security.audit import audit_logger
from app.services.analysis_pipeline import AnalysisPipeline, PipelineResult
from app.services.chain_of_custody import record_custody_event
from app.services.database import get_db
from app.services.ingestion import IngestionError, ingest_email
from app.services.models import (
    ChainOfCustodyEvent,
    CustodyEventType,
    Investigation,
)
from app.services.report_generator import (
    ForensicReport,
    ForensicReportGenerator,
)

router = APIRouter(
    prefix="/api/investigations",
    tags=["Investigations"],
)


class InvestigationResponse(BaseModel):
    investigation_id: str
    evidence_id: str
    filename: str
    sha256: str
    status: str

    verdict: str
    risk_score: float
    confidence: float

    executive_summary: str
    evidence_integrity: str

    findings: list[str]
    threat_findings: list[str]
    indicators: list[str]

    urls: list[str]
    domains: list[str]
    ip_addresses: list[str]

    authentication: dict[str, object]
    identity: dict[str, object]
    url_analysis: list[str]
    attachment_analysis: list[str]
    behavioral_analysis: list[str]

    infrastructure: list[dict[str, object]]

    correlated_findings: list[dict[str, object]]
    timeline: list[dict[str, object]]

    evidence_graph: list[dict[str, object]]

    counterfactual_scenarios: list[dict[str, object]]
    counterfactual_questions: list[str]

    custody: list[dict[str, object]] = Field(
        default_factory=list
    )


class InvestigationSummary(BaseModel):
    investigation_id: str
    evidence_id: str
    filename: str
    sha256: str
    status: str
    verdict: str
    risk_score: float
    confidence: float


@router.post(
    "/analyze",
    response_model=InvestigationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def analyze_investigation(
    file: Annotated[UploadFile, File(...)],
    db: Annotated[Session, Depends(get_db)],
) -> InvestigationResponse:
    """Acquire, preserve, analyze, persist, and report an email."""

    if not file.filename:
        audit_logger.record(
            action="investigation_upload",
            outcome="rejected",
            metadata={
                "reason": "missing_filename",
            },
        )

        raise HTTPException(
            status_code=400,
            detail="Evidence filename is required.",
        )

    media_type = (
        file.content_type
        or "application/octet-stream"
    )

    data = await file.read()

    if not data:
        audit_logger.record(
            action="investigation_upload",
            outcome="rejected",
            metadata={
                "reason": "empty_evidence",
                "filename": file.filename,
            },
        )

        raise HTTPException(
            status_code=400,
            detail="Evidence file is empty.",
        )

    if len(data) > settings.max_email_size_bytes:
        audit_logger.record(
            action="investigation_upload",
            outcome="rejected",
            metadata={
                "reason": "size_limit_exceeded",
                "filename": file.filename,
                "size_bytes": len(data),
                "configured_limit_bytes": (
                    settings.max_email_size_bytes
                ),
            },
        )

        raise HTTPException(
            status_code=413,
            detail=(
                f"Evidence exceeds the configured "
                f"{settings.max_email_size_mb} MB limit."
            ),
        )

    try:
        investigation = ingest_email(
            db=db,
            data=data,
            filename=file.filename,
            media_type=media_type,
        )

        audit_logger.record(
            action="investigation_created",
            outcome="success",
            investigation_id=investigation.investigation_id,
            evidence_id=investigation.evidence_id,
            metadata={
                "filename": file.filename,
                "media_type": media_type,
                "size_bytes": len(data),
            },
        )

    except IngestionError as exc:
        audit_logger.record(
            action="investigation_ingestion",
            outcome="failed",
            metadata={
                "filename": file.filename,
                "reason": str(exc),
            },
        )

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    try:
        investigation.status = "analyzing"

        audit_logger.record(
            action="analysis_started",
            outcome="success",
            investigation_id=investigation.investigation_id,
            evidence_id=investigation.evidence_id,
        )

        record_custody_event(
            db=db,
            investigation_id=investigation.investigation_id,
            evidence_sha256=investigation.evidence_sha256,
            event_type=CustodyEventType.ANALYSIS_STARTED,
            actor="sentinel-ai",
            description="Forensic analysis started.",
        )

        db.commit()

        result = AnalysisPipeline().analyze(data)

        audit_logger.record(
            action="analysis_completed",
            outcome="success",
            investigation_id=investigation.investigation_id,
            evidence_id=investigation.evidence_id,
            metadata={
                "verdict": result.risk.verdict,
                "risk_score": result.risk.score,
                "confidence": result.risk.confidence,
                "indicator_count": len(result.indicators),
                "url_count": len(result.urls),
                "domain_count": len(result.domains),
                "ip_count": len(result.ip_addresses),
            },
        )

        record_custody_event(
            db=db,
            investigation_id=investigation.investigation_id,
            evidence_sha256=investigation.evidence_sha256,
            event_type=CustodyEventType.ANALYSIS_COMPLETED,
            actor="sentinel-ai",
            description=(
                "Forensic analysis completed successfully."
            ),
        )

        report = ForensicReportGenerator().generate(
            investigation_id=investigation.investigation_id,
            evidence_sha256=investigation.evidence_sha256,
            risk=result.risk,
            findings=result.threat_findings,
            indicators=result.indicators,
            correlated_findings=result.correlated_findings,
            timeline=result.timeline,
        )

        investigation.analysis_result = _serialize(result)
        investigation.forensic_report = _serialize(report)

        record_custody_event(
            db=db,
            investigation_id=investigation.investigation_id,
            evidence_sha256=investigation.evidence_sha256,
            event_type=CustodyEventType.REPORT_GENERATED,
            actor="sentinel-ai",
            description=(
                "Forensic investigation report generated."
            ),
        )

        audit_logger.record(
            action="report_generated",
            outcome="success",
            investigation_id=investigation.investigation_id,
            evidence_id=investigation.evidence_id,
            metadata={
                "verdict": result.risk.verdict,
                "risk_score": result.risk.score,
            },
        )

        investigation.verdict = result.risk.verdict
        investigation.risk_score = result.risk.score
        investigation.confidence = result.risk.confidence
        investigation.status = "completed"

        db.commit()
        db.refresh(investigation)

    except Exception as exc:
        investigation.status = "failed"
        investigation.error_message = (
            "Forensic analysis failed."
        )

        audit_logger.record(
            action="analysis_failed",
            outcome="failed",
            investigation_id=investigation.investigation_id,
            evidence_id=investigation.evidence_id,
            metadata={
                "error_type": type(exc).__name__,
            },
        )

        try:
            record_custody_event(
                db=db,
                investigation_id=investigation.investigation_id,
                evidence_sha256=investigation.evidence_sha256,
                event_type=CustodyEventType.ANALYSIS_FAILED,
                actor="sentinel-ai",
                description="Forensic analysis failed.",
            )
        except Exception:
            pass

        db.commit()

        raise HTTPException(
            status_code=500,
            detail="Forensic analysis failed.",
        ) from exc

    return _build_response(
        investigation=investigation,
        result=result,
        report=report,
        db=db,
    )


@router.get(
    "",
    response_model=list[InvestigationSummary],
)
def list_investigations(
    db: Annotated[Session, Depends(get_db)],
) -> list[InvestigationSummary]:
    """Return investigations ordered from newest to oldest."""

    investigations = list(
        db.scalars(
            select(Investigation).order_by(
                Investigation.created_at.desc()
            )
        )
    )

    audit_logger.record(
        action="investigation_list",
        outcome="success",
        metadata={
            "result_count": len(investigations),
        },
    )

    return [
        InvestigationSummary(
            investigation_id=item.investigation_id,
            evidence_id=item.evidence_id,
            filename=item.original_filename,
            sha256=item.evidence_sha256,
            status=item.status,
            verdict=item.verdict or "unknown",
            risk_score=float(
                item.risk_score or 0.0
            ),
            confidence=float(
                item.confidence or 0.0
            ),
        )
        for item in investigations
    ]


@router.get(
    "/{investigation_id}/custody",
)
def get_custody_history(
    investigation_id: str,
    db: Annotated[Session, Depends(get_db)],
) -> list[dict[str, object]]:
    """Return the complete chain-of-custody history."""

    investigation = db.scalar(
        select(Investigation).where(
            Investigation.investigation_id
            == investigation_id
        )
    )

    if investigation is None:
        audit_logger.record(
            action="custody_history_access",
            outcome="not_found",
            investigation_id=investigation_id,
        )

        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    events = list(
        db.scalars(
            select(ChainOfCustodyEvent)
            .where(
                ChainOfCustodyEvent.investigation_id
                == investigation_id
            )
            .order_by(
                ChainOfCustodyEvent.timestamp.asc()
            )
        )
    )

    audit_logger.record(
        action="custody_history_access",
        outcome="success",
        investigation_id=investigation_id,
        evidence_id=investigation.evidence_id,
        metadata={
            "event_count": len(events),
        },
    )

    return [
        {
            "id": event.id,
            "investigation_id": event.investigation_id,
            "event_type": event.event_type,
            "evidence_sha256": event.evidence_sha256,
            "timestamp": event.timestamp.isoformat(),
            "actor": event.actor,
            "description": event.description,
        }
        for event in events
    ]


@router.get(
    "/{investigation_id}",
)
def get_investigation(
    investigation_id: str,
    db: Annotated[Session, Depends(get_db)],
) -> dict[str, object]:
    """Retrieve a persisted investigation and its analysis."""

    investigation = db.scalar(
        select(Investigation).where(
            Investigation.investigation_id
            == investigation_id
        )
    )

    if investigation is None:
        audit_logger.record(
            action="investigation_access",
            outcome="not_found",
            investigation_id=investigation_id,
        )

        raise HTTPException(
            status_code=404,
            detail="Investigation not found.",
        )

    custody_events = list(
        db.scalars(
            select(ChainOfCustodyEvent)
            .where(
                ChainOfCustodyEvent.investigation_id
                == investigation_id
            )
            .order_by(
                ChainOfCustodyEvent.timestamp.asc()
            )
        )
    )

    analysis: object | None = None
    report: object | None = None

    if investigation.analysis_result:
        try:
            analysis = json.loads(
                investigation.analysis_result
            )
        except json.JSONDecodeError:
            analysis = {
                "error": (
                    "Persisted analysis result "
                    "could not be decoded."
                )
            }

    if investigation.forensic_report:
        try:
            report = json.loads(
                investigation.forensic_report
            )
        except json.JSONDecodeError:
            report = {
                "error": (
                    "Persisted forensic report "
                    "could not be decoded."
                )
            }

    audit_logger.record(
        action="investigation_access",
        outcome="success",
        investigation_id=investigation_id,
        evidence_id=investigation.evidence_id,
        metadata={
            "status": investigation.status,
            "verdict": investigation.verdict or "unknown",
        },
    )

    return {
        "investigation_id": investigation.investigation_id,
        "evidence_id": investigation.evidence_id,
        "filename": investigation.original_filename,
        "sha256": investigation.evidence_sha256,
        "media_type": investigation.media_type,
        "evidence_size_bytes": (
            investigation.evidence_size_bytes
        ),
        "status": investigation.status,
        "verdict": investigation.verdict or "unknown",
        "risk_score": float(
            investigation.risk_score or 0.0
        ),
        "confidence": float(
            investigation.confidence or 0.0
        ),
        "created_at": (
            investigation.created_at.isoformat()
        ),
        "updated_at": (
            investigation.updated_at.isoformat()
        ),
        "error_message": investigation.error_message,
        "analysis": analysis,
        "report": report,
        "custody": [
            {
                "id": event.id,
                "event_type": event.event_type,
                "timestamp": event.timestamp.isoformat(),
                "actor": event.actor,
                "description": event.description,
                "evidence_sha256": event.evidence_sha256,
            }
            for event in custody_events
        ],
    }


def _serialize(value: object) -> str:
    """Serialize a dataclass or compatible object to JSON."""

    if is_dataclass(value) and not isinstance(
        value,
        type,
    ):
        payload: Any = asdict(value)
    elif isinstance(value, dict):
        payload = value
    else:
        payload = {
            "value": str(value),
        }

    return json.dumps(
        payload,
        default=str,
        ensure_ascii=False,
    )


def _build_response(
    *,
    investigation: Investigation,
    result: PipelineResult,
    report: ForensicReport,
    db: Session,
) -> InvestigationResponse:
    """Build the complete API response."""

    timeline: list[dict[str, object]] = [
        {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "title": event.title,
            "description": event.description,
            "source": event.source,
        }
        for event in result.timeline
    ]

    correlated_findings: list[dict[str, object]] = [
        {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "supporting_indicators": (
                finding.supporting_indicators
            ),
        }
        for finding in result.correlated_findings
    ]

    counterfactual_scenarios: list[dict[str, object]] = [
        {
            "scenario_id": scenario.scenario_id,
            "removed_indicator": (
                scenario.removed_indicator
            ),
            "original_score": scenario.original_score,
            "counterfactual_score": (
                scenario.counterfactual_score
            ),
            "score_delta": scenario.score_delta,
            "original_verdict": (
                scenario.original_verdict
            ),
            "counterfactual_verdict": (
                scenario.counterfactual_verdict
            ),
            "explanation": scenario.explanation,
        }
        for scenario in result.counterfactual.scenarios
    ]

    custody_events = list(
        db.scalars(
            select(ChainOfCustodyEvent)
            .where(
                ChainOfCustodyEvent.investigation_id
                == investigation.investigation_id
            )
            .order_by(
                ChainOfCustodyEvent.timestamp.asc()
            )
        )
    )

    custody: list[dict[str, object]] = [
        {
            "id": event.id,
            "event_type": event.event_type,
            "timestamp": event.timestamp.isoformat(),
            "actor": event.actor,
            "description": event.description,
            "evidence_sha256": event.evidence_sha256,
        }
        for event in custody_events
    ]

    return InvestigationResponse(
        investigation_id=(
            investigation.investigation_id
        ),
        evidence_id=investigation.evidence_id,
        filename=investigation.original_filename,
        sha256=investigation.evidence_sha256,
        status=investigation.status,
        verdict=result.risk.verdict,
        risk_score=result.risk.score,
        confidence=result.risk.confidence,
        executive_summary=(
            report.executive_summary
        ),
        evidence_integrity=(
            report.evidence_integrity
        ),
        findings=result.findings,
        threat_findings=result.threat_findings,
        indicators=result.indicators,
        urls=result.urls,
        domains=result.domains,
        ip_addresses=result.ip_addresses,
        authentication={
            "findings": result.authentication_findings,
            "indicators": (
                result.authentication_indicators
            ),
        },
        identity={
            "findings": result.identity_findings,
            "indicators": result.identity_indicators,
            "sender": result.email.sender,
            "reply_to": result.email.reply_to,
            "return_path": result.email.return_path,
        },
        url_analysis=result.url_findings,
        attachment_analysis=(
            result.attachment_findings
        ),
        behavioral_analysis=(
            result.behavioral_findings
        ),
        infrastructure=result.infrastructure,
        correlated_findings=correlated_findings,
        timeline=timeline,
        evidence_graph=_build_evidence_graph(
            result=result
        ),
        counterfactual_scenarios=(
            counterfactual_scenarios
        ),
        counterfactual_questions=(
            report.counterfactual_questions
        ),
        custody=custody,
    )


def _build_evidence_graph(
    *,
    result: PipelineResult,
) -> list[dict[str, object]]:
    """Build a forensic attack/evidence relationship graph."""

    nodes: list[dict[str, object]] = [
        {
            "id": "email",
            "type": "email",
            "label": "Email Evidence",
        }
    ]

    edges: list[dict[str, object]] = []

    def add_node(
        node_id: str,
        node_type: str,
        label: str,
        **metadata: object,
    ) -> None:
        if any(
            node["id"] == node_id
            for node in nodes
        ):
            return

        node: dict[str, object] = {
            "id": node_id,
            "type": node_type,
            "label": label,
            **metadata,
        }

        nodes.append(node)

    def add_edge(
        source: str,
        target: str,
        relationship: str,
    ) -> None:
        edge: dict[str, object] = {
            "source": source,
            "target": target,
            "relationship": relationship,
        }

        if edge not in edges:
            edges.append(edge)

    if result.email.sender:
        add_node(
            "sender",
            "identity",
            result.email.sender,
        )

        add_edge(
            "email",
            "sender",
            "sender",
        )

    for index, domain in enumerate(
        result.domains,
        start=1,
    ):
        node_id = f"domain_{index}"

        add_node(
            node_id,
            "domain",
            domain,
        )

        add_edge(
            "email",
            node_id,
            "references_domain",
        )

    for index, url in enumerate(
        result.urls,
        start=1,
    ):
        node_id = f"url_{index}"

        add_node(
            node_id,
            "url",
            url,
        )

        add_edge(
            "email",
            node_id,
            "contains_url",
        )

    for index, ip in enumerate(
        result.ip_addresses,
        start=1,
    ):
        node_id = f"ip_{index}"

        add_node(
            node_id,
            "infrastructure",
            ip,
        )

        add_edge(
            "email",
            node_id,
            "references_infrastructure",
        )

    if result.authentication_indicators:
        add_node(
            "authentication",
            "authentication",
            "Authentication Evidence",
        )

        add_edge(
            "email",
            "authentication",
            "has_authentication_evidence",
        )

        for indicator in (
            result.authentication_indicators
        ):
            indicator_id = f"auth_{indicator}"

            add_node(
                indicator_id,
                "authentication_finding",
                indicator,
            )

            add_edge(
                "authentication",
                indicator_id,
                "produces_finding",
            )

    for index, finding in enumerate(
        result.correlated_findings,
        start=1,
    ):
        node_id = f"finding_{index}"

        add_node(
            node_id,
            "threat",
            finding.title,
            severity=finding.severity,
            confidence=finding.confidence,
        )

        add_edge(
            "email",
            node_id,
            "supports_finding",
        )

        for indicator in (
            finding.supporting_indicators
        ):
            indicator_id = (
                f"indicator_{indicator}"
            )

            add_node(
                indicator_id,
                "indicator",
                indicator,
            )

            add_edge(
                indicator_id,
                node_id,
                "supports",
            )

    return [
        {
            "nodes": nodes,
            "edges": edges,
        }
    ]


__all__ = [
    "InvestigationResponse",
    "InvestigationSummary",
    "analyze_investigation",
    "get_custody_history",
    "get_investigation",
    "list_investigations",
    "router",
]