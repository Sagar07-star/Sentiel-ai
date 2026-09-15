"""
Sentinel AI
Security Audit Logging

Structured audit events for security-sensitive application actions.

The audit logger intentionally avoids storing:
- email body contents
- attachment contents
- credentials
- authorization tokens
- raw secrets

It records investigation identifiers and operational metadata only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Normalized security audit event."""

    action: str
    outcome: str
    actor: str = "system"
    investigation_id: str | None = None
    evidence_id: str | None = None
    request_id: str | None = None
    source: str = "sentinel-ai"
    timestamp: datetime = datetime.now(UTC)


class AuditLogger:
    """Emit structured, security-focused audit events."""

    def __init__(self) -> None:
        self._logger = structlog.get_logger("sentinel.audit")

    def record(
        self,
        *,
        action: str,
        outcome: str,
        actor: str = "system",
        investigation_id: str | None = None,
        evidence_id: str | None = None,
        request_id: str | None = None,
        source: str = "sentinel-ai",
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Record a structured audit event."""

        event = AuditEvent(
            action=action,
            outcome=outcome,
            actor=actor,
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            request_id=request_id,
            source=source,
            timestamp=datetime.now(UTC),
        )

        safe_metadata = self._sanitize_metadata(
            metadata or {}
        )

        self._logger.info(
            "security_audit",
            action=event.action,
            outcome=event.outcome,
            actor=event.actor,
            investigation_id=event.investigation_id,
            evidence_id=event.evidence_id,
            request_id=event.request_id,
            source=event.source,
            timestamp=event.timestamp.isoformat(),
            metadata=safe_metadata,
        )

        return event

    @staticmethod
    def _sanitize_metadata(
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Remove fields that must never enter audit logs."""

        blocked_names = {
            "password",
            "passwd",
            "secret",
            "token",
            "authorization",
            "cookie",
            "set_cookie",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "email_body",
            "body",
            "attachment_data",
            "raw_email",
            "raw_message",
        }

        safe: dict[str, Any] = {}

        for key, value in metadata.items():
            normalized_key = key.lower().replace("-", "_")

            if normalized_key in blocked_names:
                continue

            if isinstance(
                value,
                (str, int, float, bool),
            ) or value is None:
                safe[key] = value
            else:
                safe[key] = str(value)

        return safe


audit_logger = AuditLogger()


def configure_audit_logging() -> None:
    """Configure structured application logging."""

    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
    )


__all__ = [
    "AuditEvent",
    "AuditLogger",
    "audit_logger",
    "configure_audit_logging",
]