
"""
Sentinel AI
Forensic Email Parser

Parses RFC-compliant email evidence without executing content.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parsedate_to_datetime


@dataclass(slots=True)
class ParsedHeader:
    name: str
    value: str


@dataclass(slots=True)
class ParsedAttachment:
    filename: str
    content_type: str
    size_bytes: int
    content_id: str | None = None
    data: bytes = b""


@dataclass(slots=True)
class ParsedEmail:
    subject: str
    sender: str
    recipients: list[str]
    reply_to: str | None
    return_path: str | None

    date: str | None
    headers: list[ParsedHeader]

    plain_text: str
    html: str

    attachments: list[ParsedAttachment]

    authentication_results: str | None
    received_headers: list[str]

    metadata: dict[str, str] = field(default_factory=dict)


class EmailParserError(Exception):
    """Raised when an email cannot be safely parsed."""


class EmailParser:
    """Safe forensic parser for raw RFC email bytes."""

    def parse(self, data: bytes) -> ParsedEmail:
        """
        Parse raw email bytes.

        Parsing only interprets structure. Attachments and message
        content are never executed.
        """
        if not isinstance(data, bytes):
            raise EmailParserError(
                "Email evidence must be supplied as bytes."
            )

        if not data:
            raise EmailParserError(
                "Cannot parse empty email evidence."
            )

        try:
            message = BytesParser(
                policy=policy.default,
            ).parsebytes(data)
        except Exception as exc:
            raise EmailParserError(
                "Unable to parse email evidence."
            ) from exc

        return self._extract(message)

    def _extract(self, message: EmailMessage) -> ParsedEmail:
        """Extract normalized forensic fields."""
        headers = [
            ParsedHeader(
                name=name,
                value=str(value),
            )
            for name, value in message.raw_items()
        ]

        subject = self._header_value(message, "Subject")
        sender = self._header_value(message, "From")

        recipients = self._extract_addresses(
            message,
            "To",
        )

        cc_recipients = self._extract_addresses(
            message,
            "Cc",
        )

        if cc_recipients:
            recipients.extend(cc_recipients)

        reply_to = self._header_value(
            message,
            "Reply-To",
        )

        return_path = self._header_value(
            message,
            "Return-Path",
        )

        date = self._normalize_date(
            self._header_value(message, "Date")
        )

        authentication_results = self._header_value(
            message,
            "Authentication-Results",
        )

        received_headers = [
            str(value)
            for name, value in message.raw_items()
            if name.lower() == "received"
        ]

        plain_text, html = self._extract_bodies(message)
        attachments = self._extract_attachments(message)

        return ParsedEmail(
            subject=subject,
            sender=sender,
            recipients=recipients,
            reply_to=reply_to,
            return_path=return_path,
            date=date,
            headers=headers,
            plain_text=plain_text,
            html=html,
            attachments=attachments,
            authentication_results=authentication_results,
            received_headers=received_headers,
            metadata={
                "content_type": message.get_content_type(),
                "mime_version": self._header_value(
                    message,
                    "MIME-Version",
                ),
            },
        )

    @staticmethod
    def _header_value(
        message: EmailMessage,
        name: str,
    ) -> str:
        """Return a decoded header value or an empty string."""
        value = message.get(name)

        if value is None:
            return ""

        return str(value).strip()

    @staticmethod
    def _extract_addresses(
        message: EmailMessage,
        header_name: str,
    ) -> list[str]:
        """Extract mailbox addresses from a recipient header."""
        header = message.get(header_name)

        if header is None:
            return []

        try:
            addresses = header.addresses
        except AttributeError:
            return []

        return [
            str(address.addr_spec).strip()
            for address in addresses
            if address.addr_spec
        ]

    @staticmethod
    def _normalize_date(value: str) -> str | None:
        """Normalize a valid RFC email date to ISO format."""
        if not value:
            return None

        try:
            parsed = parsedate_to_datetime(value)
            return parsed.isoformat()
        except (TypeError, ValueError, OverflowError):
            return value

    @staticmethod
    def _extract_bodies(
        message: EmailMessage,
    ) -> tuple[str, str]:
        """Extract text and HTML bodies without executing anything."""
        plain_parts: list[str] = []
        html_parts: list[str] = []

        for part in message.walk():
            if part.is_multipart():
                continue

            content_type = part.get_content_type()

            if content_type not in {
                "text/plain",
                "text/html",
            }:
                continue

            try:
                content = part.get_content()
            except Exception:
                continue

            if not isinstance(content, str):
                continue

            if content_type == "text/plain":
                plain_parts.append(content)
            elif content_type == "text/html":
                html_parts.append(content)

        return (
            "\n".join(plain_parts),
            "\n".join(html_parts),
        )

    @staticmethod
    def _extract_attachments(
        message: EmailMessage,
    ) -> list[ParsedAttachment]:
        """
        Extract attachment metadata and decoded raw bytes.

        The bytes are preserved strictly as evidence for static analysis.
        They are never executed.
        """
        attachments: list[ParsedAttachment] = []

        for part in message.walk():
            if part.is_multipart():
                continue

            filename = part.get_filename()

            if not filename:
                continue

            try:
                payload = part.get_payload(decode=True)

                if not isinstance(payload, bytes):
                    payload = b""

            except Exception:
                payload = b""

            content_id = part.get("Content-ID")

            attachments.append(
                ParsedAttachment(
                    filename=filename,
                    content_type=part.get_content_type(),
                    size_bytes=len(payload),
                    content_id=content_id,
                    data=payload,
                )
            )

        return attachments


__all__ = [
    "EmailParser",
    "EmailParserError",
    "ParsedAttachment",
    "ParsedEmail",
    "ParsedHeader",
]

