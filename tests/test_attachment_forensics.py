from app.parsers.attachment_forensics import AttachmentAnalyzer


def test_normal_pdf() -> None:
    analyzer = AttachmentAnalyzer()

    result = analyzer.analyze(
        filename="report.pdf",
        data=b"%PDF-test",
        declared_content_type="application/pdf",
    )

    assert result.extension == ".pdf"
    assert result.size_bytes == 9
    assert result.suspicious is False


def test_executable_attachment() -> None:
    analyzer = AttachmentAnalyzer()

    result = analyzer.analyze(
        filename="invoice.exe",
        data=b"MZ-test",
        declared_content_type="application/octet-stream",
    )

    assert result.suspicious is True
    assert "executable_or_script_extension" in result.indicators


def test_macro_document() -> None:
    analyzer = AttachmentAnalyzer()

    result = analyzer.analyze(
        filename="invoice.xlsm",
        data=b"test-document",
        declared_content_type=(
            "application/vnd.ms-excel.sheet.macroEnabled.12"
        ),
    )

    assert result.suspicious is True
    assert "macro_capable_document" in result.indicators


def test_double_extension() -> None:
    analyzer = AttachmentAnalyzer()

    result = analyzer.analyze(
        filename="invoice.pdf.exe",
        data=b"MZ-test",
        declared_content_type="application/octet-stream",
    )

    assert result.suspicious is True
    assert "double_extension" in result.indicators


def test_hash_is_deterministic() -> None:
    analyzer = AttachmentAnalyzer()

    result = analyzer.analyze(
        filename="sample.txt",
        data=b"sentinel evidence",
        declared_content_type="text/plain",
    )

    assert len(result.sha256) == 64