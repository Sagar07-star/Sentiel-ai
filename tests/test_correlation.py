from app.services.correlation import EvidenceCorrelator


def test_identity_authentication_correlation() -> None:
    correlator = EvidenceCorrelator()

    findings = correlator.correlate(
        indicators=[
            "spf_fail",
            "reply_to_domain_mismatch",
        ],
    )

    assert len(findings) == 1
    assert findings[0].finding_id == "identity_authentication_conflict"
    assert findings[0].severity == "high"
    assert findings[0].confidence > 0.8


def test_credential_harvesting_correlation() -> None:
    correlator = EvidenceCorrelator()

    findings = correlator.correlate(
        indicators=[
            "suspicious_keywords",
            "behavior_credential_request",
        ],
    )

    assert findings[0].finding_id == "credential_harvesting_pattern"


def test_multiple_correlations() -> None:
    correlator = EvidenceCorrelator()

    findings = correlator.correlate(
        indicators=[
            "spf_fail",
            "reply_to_domain_mismatch",
            "suspicious_keywords",
            "behavior_credential_request",
        ],
    )

    assert len(findings) == 2


def test_no_correlation_from_unrelated_signal() -> None:
    correlator = EvidenceCorrelator()

    findings = correlator.correlate(
        indicators=["non_https"],
    )

    assert findings == []