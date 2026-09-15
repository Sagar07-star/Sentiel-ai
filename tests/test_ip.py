from app.intelligence.ip import IPAnalyzer


def test_public_ip_with_intelligence() -> None:
    analyzer = IPAnalyzer()

    result = analyzer.analyze(
        "8.8.8.8",
        country="United States",
        region="California",
        city="Mountain View",
        latitude=37.4056,
        longitude=-122.0775,
        asn="AS15169",
        organization="Google LLC",
        network_type="hosting",
        source="test-provider",
    )

    assert result.valid is True
    assert result.is_private is False
    assert result.country == "United States"
    assert result.asn == "AS15169"
    assert result.organization == "Google LLC"
    assert any(
        "infrastructure" in finding.lower()
        for finding in result.findings
    )


def test_private_ip() -> None:
    analyzer = IPAnalyzer()

    result = analyzer.analyze("192.168.1.10")

    assert result.valid is True
    assert result.is_private is True


def test_invalid_ip() -> None:
    analyzer = IPAnalyzer()

    result = analyzer.analyze("999.999.999.999")

    assert result.valid is False
    assert result.country is None
    assert result.asn is None