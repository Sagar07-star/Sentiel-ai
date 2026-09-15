from app.detectors.url_risk import URLRiskAnalyzer


def test_normal_https_url() -> None:
    analyzer = URLRiskAnalyzer()

    result = analyzer.analyze("https://example.com/about")

    assert result.score == 0.0
    assert result.indicators == []


def test_ip_based_url() -> None:
    analyzer = URLRiskAnalyzer()

    result = analyzer.analyze("http://192.168.1.10/login")

    assert "ip_based_url" in result.indicators
    assert "non_https" in result.indicators
    assert result.score > 0.0


def test_shortened_url() -> None:
    analyzer = URLRiskAnalyzer()

    result = analyzer.analyze("https://bit.ly/abc123")

    assert "url_shortener" in result.indicators


def test_suspicious_keywords() -> None:
    analyzer = URLRiskAnalyzer()

    result = analyzer.analyze(
        "https://secure.example.com/account/verify/login"
    )

    assert "suspicious_keywords" in result.indicators
    assert result.score > 0.0