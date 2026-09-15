from email.message import EmailMessage

from app.parsers.mime_forensics import MIMEForensics


def test_mime_analysis() -> None:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "analyst@example.com"
    message["Subject"] = "Test"
    message.set_content("Hello")

    message.add_attachment(
        b"test-data",
        maintype="application",
        subtype="octet-stream",
        filename="sample.bin",
    )

    analyzer = MIMEForensics()
    result = analyzer.analyze(message)

    assert result.part_count >= 2
    assert result.attachment_count == 1
    assert "sample.bin" in result.filenames


def test_embedded_binary_is_flagged() -> None:
    message = EmailMessage()
    message.set_content("Test")

    message.add_attachment(
        b"MZ-test",
        maintype="application",
        subtype="x-msdownload",
        filename="payload.exe",
    )

    analyzer = MIMEForensics()
    result = analyzer.analyze(message)

    assert result.embedded_object_count == 1
    assert result.suspicious is True
    assert "embedded_binary_object" in result.indicators