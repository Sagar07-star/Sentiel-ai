from app.services.analysis_pipeline import AnalysisPipeline


def test_complete_analysis_pipeline() -> None:
    email = (
        b"From: alerts@example.com\r\n"
        b"To: analyst@example.com\r\n"
        b"Reply-To: attacker@evil.example\r\n"
        b"Subject: Urgent account verification\r\n"
        b"Date: Thu, 03 Sep 2026 12:00:00 +0000\r\n"
        b"Authentication-Results: mx.example.com; "
        b"spf=fail smtp.mailfrom=evil.example; "
        b"dmarc=fail header.from=example.com\r\n"
        b"Received: from mail.example.com; "
        b"Thu, 03 Sep 2026 11:00:00 +0000\r\n"
        b"\r\n"
        b"Verify your account immediately. "
        b"Visit http://192.168.1.10/login "
        b"and enter your password."
    )

    result = AnalysisPipeline().analyze(email)

    assert result.email.subject == "Urgent account verification"
    assert result.urls
    assert "192.168.1.10" in result.ip_addresses

    assert "spf_fail" in result.indicators
    assert "dmarc_fail" in result.indicators
    assert "reply_to_domain_mismatch" in result.indicators
    assert "behavior_credential_request" in result.indicators
    assert "ip_based_url" in result.indicators

    assert result.risk.score > 0
    assert result.risk.verdict in {
        "low",
        "medium",
        "high",
        "critical",
    }

    assert result.counterfactual.scenarios
    assert result.timeline


def test_benign_pipeline_has_low_risk() -> None:
    email = (
        b"From: team@example.com\r\n"
        b"To: analyst@example.com\r\n"
        b"Subject: Team lunch\r\n"
        b"Date: Thu, 03 Sep 2026 12:00:00 +0000\r\n"
        b"\r\n"
        b"See you tomorrow at noon."
    )

    result = AnalysisPipeline().analyze(email)

    assert result.risk.score == 0.0
    assert result.risk.verdict == "minimal"