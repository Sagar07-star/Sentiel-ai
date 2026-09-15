
"""
Sentinel AI
Deep Attachment Forensics

Performs static inspection of email attachments.

Attachments are treated strictly as untrusted evidence.
They are never executed, imported, opened by external applications,
or otherwise activated.
"""

from __future__ import annotations

import hashlib
import mimetypes
import re
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import PurePath


@dataclass(frozen=True, slots=True)
class AttachmentAnalysis:
    filename: str
    extension: str
    declared_content_type: str
    detected_content_type: str | None
    detected_file_type: str | None
    size_bytes: int
    sha256: str

    extension_mismatch: bool
    signature_mismatch: bool

    archive: bool
    archive_entries: list[str]
    suspicious_archive_entries: list[str]

    macro_capable: bool
    macro_detected: bool
    embedded_object_detected: bool

    suspicious: bool
    findings: list[str]
    indicators: list[str]
    embedded_urls: list[str]


class AttachmentAnalyzer:
    """Perform safe static attachment analysis."""

    SUSPICIOUS_EXTENSIONS = {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".hta",
        ".msi",
        ".dll",
    }

    MACRO_EXTENSIONS = {
        ".docm",
        ".xlsm",
        ".pptm",
        ".dotm",
        ".xltm",
        ".potm",
    }

    ARCHIVE_EXTENSIONS = {
        ".zip",
        ".rar",
        ".7z",
        ".iso",
    }

    DOUBLE_EXTENSION_PATTERN = (
        ".pdf.exe",
        ".doc.exe",
        ".docx.exe",
        ".xls.exe",
        ".xlsx.exe",
        ".jpg.exe",
        ".png.exe",
        ".txt.exe",
        ".pdf.js",
        ".doc.js",
        ".docx.js",
    )

    SUSPICIOUS_ARCHIVE_EXTENSIONS = {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".com",
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".hta",
        ".msi",
        ".dll",
        ".lnk",
    }

    MAX_ARCHIVE_ENTRIES = 1000
    MAX_ARCHIVE_ENTRY_NAME_LENGTH = 512

    FILE_SIGNATURES: tuple[tuple[str, bytes], ...] = (
        ("PE executable", b"MZ"),
        ("PDF document", b"%PDF-"),
        ("PNG image", b"\x89PNG\r\n\x1a\n"),
        ("JPEG image", b"\xff\xd8\xff"),
        ("GIF image", b"GIF8"),
        ("ZIP/OOXML container", b"PK\x03\x04"),
        ("GZIP archive", b"\x1f\x8b"),
        ("RAR archive", b"Rar!\x1a\x07"),
        ("7-Zip archive", b"7z\xbc\xaf'\x1c"),
        ("Windows shortcut", b"\x4c\x00\x00\x00"),
    )

    URL_PATTERN = re.compile(
        rb"https?://[^\s<>'\"\\]+",
        re.IGNORECASE,
    )

    def analyze(
        self,
        *,
        filename: str,
        data: bytes,
        declared_content_type: str,
    ) -> AttachmentAnalysis:
        """Analyze an attachment using metadata and static byte inspection."""

        if not filename.strip():
            raise ValueError("Attachment filename cannot be empty.")

        if not isinstance(data, bytes):
            raise TypeError("Attachment data must be bytes.")

        safe_filename = PurePath(filename).name
        extension = PurePath(safe_filename).suffix.lower()

        detected_content_type, _ = mimetypes.guess_type(safe_filename)

        sha256 = hashlib.sha256(data).hexdigest()

        findings: list[str] = []
        indicators: list[str] = []
        embedded_urls = self._extract_urls(data)

        suspicious = False

        lower_filename = safe_filename.lower()

        # ---------------------------------------------------------
        # Extension-based analysis
        # ---------------------------------------------------------

        if extension in self.SUSPICIOUS_EXTENSIONS:
            suspicious = True
            findings.append(
                "Attachment uses an executable or script-capable extension."
            )
            indicators.append("executable_or_script_extension")

        macro_capable = extension in self.MACRO_EXTENSIONS

        if macro_capable:
            suspicious = True
            findings.append(
                "Attachment uses a macro-capable Office document format."
            )
            indicators.append("macro_capable_document")

        archive = extension in self.ARCHIVE_EXTENSIONS

        if archive:
            findings.append(
                "Attachment is an archive/container and requires static "
                "content inspection."
            )
            indicators.append("archive_attachment")

        if any(
            pattern in lower_filename
            for pattern in self.DOUBLE_EXTENSION_PATTERN
        ):
            suspicious = True
            findings.append(
                "Filename contains a suspicious double-extension pattern."
            )
            indicators.append("double_extension")

        # ---------------------------------------------------------
        # MIME/content-type analysis
        # ---------------------------------------------------------

        extension_mismatch = self._extension_mismatch(
            extension=extension,
            detected_content_type=detected_content_type,
            declared_content_type=declared_content_type,
        )

        if extension_mismatch:
            suspicious = True
            findings.append(
                "Filename extension and declared/detected content type "
                "appear inconsistent."
            )
            indicators.append("extension_content_type_mismatch")

        # ---------------------------------------------------------
        # Magic-byte/signature analysis
        # ---------------------------------------------------------

        detected_file_type = self._detect_file_signature(data)

        signature_mismatch = self._signature_mismatch(
            extension=extension,
            detected_file_type=detected_file_type,
        )

        if signature_mismatch:
            suspicious = True
            findings.append(
                "Attachment content signature does not match its filename "
                "extension."
            )
            indicators.append("file_signature_mismatch")

        if detected_file_type == "PE executable":
            suspicious = True
            findings.append(
                "Attachment bytes contain a Windows PE executable signature."
            )
            indicators.append("pe_executable_signature")

        # ---------------------------------------------------------
        # Macro/static Office analysis
        # ---------------------------------------------------------

        macro_detected = self._detect_macro(data)

        if macro_detected:
            suspicious = True
            findings.append(
                "Static inspection detected VBA macro-related content."
            )
            indicators.append("macro_detected")

        # ---------------------------------------------------------
        # Embedded binary/object analysis
        # ---------------------------------------------------------

        embedded_object_detected = self._detect_embedded_objects(data)

        if embedded_object_detected:
            suspicious = True
            findings.append(
                "Static inspection detected embedded object/binary markers."
            )
            indicators.append("embedded_binary_object")

        # ---------------------------------------------------------
        # Embedded URL analysis
        # ---------------------------------------------------------

        if embedded_urls:
            findings.append(
                "Attachment contains embedded URL references that require "
                "separate URL analysis."
            )
            indicators.append("embedded_url")

        # ---------------------------------------------------------
        # Archive analysis
        # ---------------------------------------------------------

        archive_entries: list[str] = []
        suspicious_archive_entries: list[str] = []

        if extension == ".zip" or self._looks_like_zip(data):
            archive = True

            if "archive_attachment" not in indicators:
                indicators.append("archive_attachment")

            archive_entries, suspicious_archive_entries = (
                self._inspect_zip(data)
            )

            if suspicious_archive_entries:
                suspicious = True
                findings.append(
                    "Archive contains executable, script, shortcut, or "
                    "other suspicious file entries."
                )
                indicators.append("suspicious_archive_content")

        return AttachmentAnalysis(
            filename=safe_filename,
            extension=extension,
            declared_content_type=declared_content_type,
            detected_content_type=detected_content_type,
            detected_file_type=detected_file_type,
            size_bytes=len(data),
            sha256=sha256,
            extension_mismatch=extension_mismatch,
            signature_mismatch=signature_mismatch,
            archive=archive,
            archive_entries=archive_entries,
            suspicious_archive_entries=suspicious_archive_entries,
            macro_capable=macro_capable,
            macro_detected=macro_detected,
            embedded_object_detected=embedded_object_detected,
            suspicious=suspicious,
            findings=findings,
            indicators=indicators,
            embedded_urls=embedded_urls,
        )

    @staticmethod
    def _detect_file_signature(data: bytes) -> str | None:
        """Identify common file types using magic bytes."""

        for file_type, signature in AttachmentAnalyzer.FILE_SIGNATURES:
            if data.startswith(signature):
                return file_type

        # OLE Compound File signature.
        if data.startswith(
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        ):
            return "OLE Compound Document"

        return None

    @staticmethod
    def _signature_mismatch(
        *,
        extension: str,
        detected_file_type: str | None,
    ) -> bool:
        """Detect obvious extension/signature contradictions."""

        if not detected_file_type:
            return False

        expected_extensions: dict[str, set[str]] = {
            "PE executable": {
                ".exe",
                ".scr",
                ".dll",
                ".com",
            },
            "PDF document": {
                ".pdf",
            },
            "PNG image": {
                ".png",
            },
            "JPEG image": {
                ".jpg",
                ".jpeg",
            },
            "GIF image": {
                ".gif",
            },
            "ZIP/OOXML container": {
                ".zip",
                ".docx",
                ".xlsx",
                ".pptx",
                ".docm",
                ".xlsm",
                ".pptm",
                ".dotm",
                ".xltm",
                ".potm",
            },
            "RAR archive": {
                ".rar",
            },
            "7-Zip archive": {
                ".7z",
            },
            "Windows shortcut": {
                ".lnk",
            },
            "OLE Compound Document": {
                ".doc",
                ".xls",
                ".ppt",
                ".msg",
                ".vsd",
            },
        }

        allowed = expected_extensions.get(detected_file_type)

        if allowed is None:
            return False

        if not extension:
            return False

        return extension not in allowed

    @staticmethod
    def _extension_mismatch(
        *,
        extension: str,
        detected_content_type: str | None,
        declared_content_type: str,
    ) -> bool:
        """Compare filename extension against MIME expectations."""

        if not extension:
            return False

        expected_type, _ = mimetypes.guess_type(
            f"file{extension}"
        )

        if expected_type and declared_content_type:
            declared = (
                declared_content_type
                .split(";", 1)[0]
                .strip()
                .lower()
            )

            if declared and declared != expected_type.lower():
                return True

        if expected_type and detected_content_type:
            if detected_content_type.lower() != expected_type.lower():
                return True

        return False

    @staticmethod
    def _detect_macro(data: bytes) -> bool:
        """
        Detect macro-related structures without opening or executing
        the document.
        """

        lower_data = data.lower()

        markers = (
            b"vba",
            b"vba_project",
            b"vba_project.bin",
            b"word/vba",
            b"xl/vba",
            b"ppt/vba",
        )

        return any(marker in lower_data for marker in markers)

    @staticmethod
    def _detect_embedded_objects(data: bytes) -> bool:
        """Detect common static embedded-object markers."""

        lower_data = data.lower()

        markers = (
            b"oleobject",
            b"embeddedobject",
            b"embeddings/",
            b"oleobject",
            b"package",
        )

        return any(marker in lower_data for marker in markers)

    @staticmethod
    def _extract_urls(data: bytes) -> list[str]:
        """Extract URL references from raw attachment bytes."""

        matches = AttachmentAnalyzer.URL_PATTERN.findall(data)

        urls: list[str] = []

        for match in matches:
            try:
                value = match.decode(
                    "utf-8",
                    errors="ignore",
                ).rstrip(".,);]}>'\"")
            except UnicodeDecodeError:
                continue

            if value and value not in urls:
                urls.append(value)

        return urls[:500]

    @staticmethod
    def _looks_like_zip(data: bytes) -> bool:
        """Check for ZIP/OOXML magic bytes."""

        return data.startswith(
            (
                b"PK\x03\x04",
                b"PK\x05\x06",
                b"PK\x07\x08",
            )
        )

    def _inspect_zip(
        self,
        data: bytes,
    ) -> tuple[list[str], list[str]]:
        """
        Inspect ZIP/OOXML entries safely.

        Only directory metadata is read. Archive members are never
        extracted to disk or executed.
        """

        entries: list[str] = []
        suspicious_entries: list[str] = []

        try:
            with zipfile.ZipFile(BytesIO(data)) as archive:
                names = archive.namelist()

                for name in names[: self.MAX_ARCHIVE_ENTRIES]:
                    safe_name = name[: self.MAX_ARCHIVE_ENTRY_NAME_LENGTH]

                    entries.append(safe_name)

                    lower_name = safe_name.lower()

                    extension = PurePath(
                        lower_name
                    ).suffix

                    if extension in self.SUSPICIOUS_ARCHIVE_EXTENSIONS:
                        suspicious_entries.append(
                            safe_name
                        )

                    if (
                        ".." in PurePath(safe_name).parts
                        or safe_name.startswith(("/", "\\"))
                    ):
                        suspicious_entries.append(
                            safe_name
                        )

        except (
            zipfile.BadZipFile,
            OSError,
            ValueError,
        ):
            return [], []

        return (
            list(dict.fromkeys(entries)),
            list(dict.fromkeys(suspicious_entries)),
        )


__all__ = [
    "AttachmentAnalysis",
    "AttachmentAnalyzer",
]

