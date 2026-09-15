from app.detectors.identity import IdentityAnalyzer


def test_matching_identity_domains() -> None:
    analyzer = IdentityAnalyzer()

    result = analyzer.analyze(
        sender_address="alerts@example.com",
        reply_to_address="alerts@example.com",
        return_path_address="bounce@example.com",
        spf_domain="example.com",
        dkim_domain="example.com",
        dmarc_domain="example.com",
    )

    assert result.sender_domain == "example.com"
    assert result.findings == []
    assert result.indicators == []


def test_reply_to_mismatch() -> None:
    analyzer = IdentityAnalyzer()

    result = analyzer.analyze(
        sender_address="alerts@example.com",
        reply_to_address="support@evil.example",
        return_path_address="bounce@example.com",
    )

    assert "reply_to_domain_mismatch" in result.indicators


def test_return_path_mismatch() -> None:
    analyzer = IdentityAnalyzer()

    result = analyzer.analyze(
        sender_address="alerts@example.com",
        reply_to_address=None,
        return_path_address="bounce@evil.example",
    )

    assert "return_path_domain_mismatch" in result.indicators


def test_authentication_domain_mismatch() -> None:
    analyzer = IdentityAnalyzer()

    result = analyzer.analyze(
        sender_address="alerts@example.com",
        reply_to_address=None,
        return_path_address=None,
        spf_domain="mail.example.net",
        dkim_domain="example.com",
        dmarc_domain="example.com",
    )

    assert "authentication_domain_mismatch" in result.indicators