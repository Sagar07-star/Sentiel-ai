from app.extraction.indicators import IndicatorExtractor


def test_extract_urls_domains_and_ips() -> None:
    extractor = IndicatorExtractor()

    result = extractor.extract(
        plain_text=(
            "Visit https://login.example.com/account "
            "or http://192.168.1.10/login. "
            "Contact admin@example.org."
        ),
    )

    assert "https://login.example.com/account" in result.urls
    assert "http://192.168.1.10/login" in result.urls

    assert "login.example.com" in result.domains
    assert "example.org" in result.domains

    assert "192.168.1.10" in result.ip_addresses


def test_extract_from_html() -> None:
    extractor = IndicatorExtractor()

    result = extractor.extract(
        html=(
            '<a href="https://secure.example.com/login">'
            "Verify account</a>"
        ),
    )

    assert result.urls == ["https://secure.example.com/login"]
    assert "secure.example.com" in result.domains


def test_invalid_ip_is_ignored() -> None:
    extractor = IndicatorExtractor()

    result = extractor.extract(
        plain_text="Invalid IP 999.999.999.999",
    )

    assert result.ip_addresses == []


def test_duplicate_indicators_are_removed() -> None:
    extractor = IndicatorExtractor()

    result = extractor.extract(
        plain_text=(
            "https://example.com/a "
            "https://example.com/b "
            "example.com"
        ),
    )

    assert result.urls == [
        "https://example.com/a",
        "https://example.com/b",
    ]
    assert result.domains == ["example.com"]