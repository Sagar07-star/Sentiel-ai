"""
Sentinel AI
MIME Forensics

Static inspection of MIME parts and attachment metadata.
No attachment is executed or opened as a program.
"""

from __future__ import annotations

from dataclasses import dataclass
from email.message import EmailMessage


@dataclass(frozen=True, slots=True)
class MIMEAnalysis:
    part_count: int
    attachment_count: int
    content_types: list[str]
    filenames: list[str]
    embedded_object_count: int
    suspicious: bool
    findings: list[str]
    indicators: list[str]


class MIMEForensics:
    """Inspect an already-parsed email MIME tree."""

    EMBEDDED_TYPES = {
        "application/octet-stream",
        "application/x-msdownload",
        "application/x-msdos-program",
        "application/vnd.ms-office",
        "application/vnd.openxmlformats-officedocument",
    }

    def analyze(self, message: EmailMessage) -> MIMEAnalysis:
        if not isinstance(message, EmailMessage):
            raise TypeError("message must be an EmailMessage.")

        parts = list(message.walk())

        content_types: list[str] = []
        filenames: list[str] = []
        embedded_object_count = 0
        attachment_count = 0

        findings: list[str] = []
        indicators: list[str] = []

        for part in parts:
            content_type = part.get_content_type().lower()
            content_types.append(content_type)

            filename = part.get_filename()
            if filename:
                attachment_count += 1
                filenames.append(str(filename))

            if content_type in self.EMBEDDED_TYPES:
                embedded_object_count += 1

        if attachment_count:
            findings.append(
                f"Email contains {attachment_count} attachment(s)."
            )

        if embedded_object_count:
            findings.append(
                f"Email contains {embedded_object_count} "
                "potentially embedded/binary MIME object(s)."
            )
            indicators.append("embedded_binary_object")

        suspicious = bool(embedded_object_count)

        if suspicious:
            findings.append(
                "Binary MIME content requires static forensic inspection."
            )

        return MIMEAnalysis(
            part_count=len(parts),
            attachment_count=attachment_count,
            content_types=list(dict.fromkeys(content_types)),
            filenames=filenames,
            embedded_object_count=embedded_object_count,
            suspicious=suspicious,
            findings=findings,
            indicators=indicators,
        )


__all__ = [
    "MIMEAnalysis",
    "MIMEForensics",
]