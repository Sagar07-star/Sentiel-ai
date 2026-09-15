from app.intelligence.dns import DNSIntelligence


def test_dns_resolution(monkeypatch) -> None:
    def fake_gethostbyname_ex(domain: str):
        return (
            "example.com",
            [],
            ["93.184.216.34"],
        )

    monkeypatch.setattr(
        "socket.gethostbyname_ex",
        fake_gethostbyname_ex,
    )

    analyzer = DNSIntelligence()
    result = analyzer.resolve("example.com")

    assert result.resolved is True
    assert result.addresses == ["93.184.216.34"]
    assert result.canonical_name == "example.com"


def test_dns_failure(monkeypatch) -> None:
    import socket

    def fake_gethostbyname_ex(domain: str):
        raise socket.gaierror("DNS failure")

    monkeypatch.setattr(
        "socket.gethostbyname_ex",
        fake_gethostbyname_ex,
    )

    analyzer = DNSIntelligence()
    result = analyzer.resolve("does-not-exist.invalid")

    assert result.resolved is False
    assert result.addresses == []


def test_empty_domain() -> None:
    analyzer = DNSIntelligence()

    result = analyzer.resolve("")

    assert result.resolved is False
    assert result.addresses == []