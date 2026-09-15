from app.detectors.authentication import AuthenticationAnalyzer


def test_authentication_pass() -> None:
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        "mx.example.com; "
        "spf=pass smtp.mailfrom=example.com; "
        "dkim=pass header.d=example.com; "
        "dmarc=pass header.from=example.com"
    )

    assert result.spf == "pass"
    assert result.dkim == "pass"
    assert result.dmarc == "pass"
    assert result.passed is True
    assert result.failed is False


def test_authentication_failures() -> None:
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(
        "mx.example.com; "
        "spf=fail smtp.mailfrom=evil.example; "
        "dkim=fail header.d=evil.example; "
        "dmarc=fail header.from=example.com"
    )

    assert result.spf == "fail"
    assert result.dkim == "fail"
    assert result.dmarc == "fail"
    assert result.failed is True

    assert "spf_fail" in result.indicators
    assert "dkim_fail" in result.indicators
    assert "dmarc_fail" in result.indicators


def test_missing_authentication_results() -> None:
    analyzer = AuthenticationAnalyzer()

    result = analyzer.analyze(None)

    assert result.missing is True
    assert result.passed is False
    assert result.failed is False
    assert "authentication_results_missing" in result.indicators