"""
Sentinel AI
Machine-Learning Phishing Detector

Local hybrid phishing classifier.

Design:
- TF-IDF + Logistic Regression for email-language classification.
- Structural security features for URLs and social-engineering signals.
- No external network dependency.
- Deterministic built-in baseline training data.
- ML output is evidence, not attribution.
- Previously unseen URLs can still produce suspiciousness evidence from
  structural characteristics rather than requiring an exact threat-feed match.

Important:
The built-in corpus is a development baseline. It is not presented as a
validated real-world phishing dataset.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

import numpy as np
from sklearn.feature_extraction.text import (  # type: ignore[import-untyped]
    TfidfVectorizer,
)
from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]

MODEL_VERSION: Final[str] = "sentinel-local-phishing-v1"


@dataclass(frozen=True, slots=True)
class MLPhishingResult:
    """Machine-learning phishing analysis result."""

    label: str
    phishing_probability: float
    benign_probability: float
    confidence: float

    model_version: str
    trained_samples: int

    text_features: list[str]
    structural_features: list[str]
    indicators: list[str]
    findings: list[str]


class MLPhishingAnalyzer:
    """
    Local phishing classifier.

    The classifier is deliberately lightweight so Sentinel AI can run
    without an external ML service.

    The built-in corpus provides a deterministic baseline for development
    and integration testing. Production evaluation should use a properly
    curated and representative dataset.
    """

    _PHISHING_THRESHOLD: Final[float] = 0.65
    _HIGH_CONFIDENCE_THRESHOLD: Final[float] = 0.85

    _PHISHING_SAMPLES: Final[tuple[str, ...]] = (
        "urgent verify your account immediately",
        "your account will be suspended unless you confirm your password",
        "click the link to verify your identity",
        "security alert confirm your login credentials",
        "payment failed update your billing information",
        "your mailbox is full click here to increase storage",
        "invoice attached please open and confirm payment",
        "wire transfer required immediately",
        "your password expires today verify account",
        "unusual login activity confirm your account now",
        "administrator requires your credentials",
        "confirm your bank account information",
        "urgent payment request confidential",
        "click below to restore access",
        "your account has been locked verify now",
        "security department needs your password",
        "review the attached invoice immediately",
        "send the requested payment today",
        "verify employee credentials using the secure portal",
        "failure to respond will result in account termination",
        "reset your password using the link below",
        "confirm your identity to avoid suspension",
        "important security notification login verification",
        "your payment account requires immediate verification",
    )

    _BENIGN_SAMPLES: Final[tuple[str, ...]] = (
        "meeting scheduled for tomorrow at ten",
        "please find the project notes attached",
        "the quarterly report is ready for review",
        "thanks for sending the updated document",
        "team lunch has been moved to friday",
        "the deployment completed successfully",
        "here are the notes from today's meeting",
        "please review the design proposal when convenient",
        "the invoice has been approved by finance",
        "our maintenance window starts at midnight",
        "the project milestone was completed",
        "attached is the final version of the report",
        "please let me know if you have any questions",
        "the customer requested a product demonstration",
        "we will discuss the issue during the next meeting",
        "the office will be closed on monday",
        "thank you for your feedback",
        "the requested files are available in the shared folder",
        "the engineering team completed the test run",
        "please review the documentation before release",
        "the weekly status report is attached",
        "we have confirmed the meeting location",
        "the new software build is ready for testing",
        "the purchase order has been approved",
    )

    _SUSPICIOUS_TERMS: Final[tuple[str, ...]] = (
        "urgent",
        "immediately",
        "verify",
        "verification",
        "password",
        "credential",
        "credentials",
        "suspended",
        "suspension",
        "locked",
        "security alert",
        "payment",
        "wire transfer",
        "invoice",
        "confirm your identity",
        "reset your password",
        "account termination",
        "unusual login",
    )

    _URL_TERMS: Final[tuple[str, ...]] = (
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
        "billing",
        "payment",
        "confirm",
        "signin",
    )

    _SHORTENERS: Final[tuple[str, ...]] = (
        "bit.ly/",
        "tinyurl.com/",
        "t.co/",
        "goo.gl/",
        "is.gd/",
        "ow.ly/",
    )

    def __init__(self) -> None:
        self._vectorizer = TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
            ngram_range=(1, 2),
            min_df=1,
            max_features=5000,
        )

        self._model = LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        )

        self._trained = False
        self._train()

    def analyze(
        self,
        *,
        subject: str | None = None,
        body: str | None = None,
        urls: list[str] | None = None,
        domains: list[str] | None = None,
        behavioral_findings: list[str] | None = None,
    ) -> MLPhishingResult:
        """Analyze an email using the local ML model."""

        subject_text = subject or ""
        body_text = body or ""

        combined_text = self._build_text(
            subject=subject_text,
            body=body_text,
        )

        if not combined_text.strip():
            return MLPhishingResult(
                label="insufficient_evidence",
                phishing_probability=0.0,
                benign_probability=0.0,
                confidence=0.0,
                model_version=MODEL_VERSION,
                trained_samples=self._training_size(),
                text_features=[],
                structural_features=[],
                indicators=["ml_text_missing"],
                findings=[
                    "Machine-learning phishing analysis had insufficient "
                    "email text."
                ],
            )

        matrix = self._vectorizer.transform(
            [combined_text]
        )

        probabilities = self._model.predict_proba(matrix)[0]

        classes = list(self._model.classes_)

        phishing_probability = self._class_probability(
            probabilities,
            classes,
            1,
        )

        benign_probability = self._class_probability(
            probabilities,
            classes,
            0,
        )

        text_features = self._extract_text_features(
            combined_text
        )

        structural_features = self._extract_structural_features(
            urls=urls or [],
            domains=domains or [],
        )

        behavioral = behavioral_findings or []

        indicators: list[str] = []
        findings: list[str] = []

        if phishing_probability >= self._PHISHING_THRESHOLD:
            indicators.append(
                "ml_phishing_probability_high"
            )

            findings.append(
                "The local machine-learning model identified language "
                "patterns associated with phishing."
            )

        if phishing_probability >= self._HIGH_CONFIDENCE_THRESHOLD:
            indicators.append(
                "ml_phishing_probability_very_high"
            )

        if text_features:
            indicators.append(
                "ml_suspicious_language"
            )

        if structural_features:
            indicators.append(
                "ml_suspicious_structure"
            )

        if behavioral:
            indicators.append(
                "ml_behavioral_context"
            )

        if (
            phishing_probability >= self._PHISHING_THRESHOLD
            and structural_features
        ):
            indicators.append(
                "ml_text_and_structure_correlation"
            )

            findings.append(
                "Phishing-associated language is supported by suspicious "
                "message or URL structure."
            )

        if (
            phishing_probability >= self._PHISHING_THRESHOLD
            and behavioral
        ):
            indicators.append(
                "ml_text_and_behavior_correlation"
            )

            findings.append(
                "Phishing-associated language is consistent with observed "
                "social-engineering behavior."
            )

        label = (
            "phishing"
            if phishing_probability >= self._PHISHING_THRESHOLD
            else "benign"
        )

        confidence = self._confidence(
            phishing_probability,
            text_features=text_features,
            structural_features=structural_features,
        )

        if not findings:
            findings.append(
                "The local machine-learning model did not identify "
                "strong phishing language evidence."
            )

        return MLPhishingResult(
            label=label,
            phishing_probability=round(
                phishing_probability,
                4,
            ),
            benign_probability=round(
                benign_probability,
                4,
            ),
            confidence=round(
                confidence,
                4,
            ),
            model_version=MODEL_VERSION,
            trained_samples=self._training_size(),
            text_features=text_features,
            structural_features=structural_features,
            indicators=list(
                dict.fromkeys(indicators)
            ),
            findings=list(
                dict.fromkeys(findings)
            ),
        )

    def _train(self) -> None:
        """Train the local baseline classifier."""

        texts = [
            *self._BENIGN_SAMPLES,
            *self._PHISHING_SAMPLES,
        ]

        labels = [
            *([0] * len(self._BENIGN_SAMPLES)),
            *([1] * len(self._PHISHING_SAMPLES)),
        ]

        matrix = self._vectorizer.fit_transform(
            texts
        )

        self._model.fit(
            matrix,
            np.asarray(labels),
        )

        self._trained = True

    def _training_size(self) -> int:
        """Return the number of baseline training samples."""

        return (
            len(self._BENIGN_SAMPLES)
            + len(self._PHISHING_SAMPLES)
        )

    @staticmethod
    def _build_text(
        *,
        subject: str,
        body: str,
    ) -> str:
        """Combine useful natural-language evidence."""

        parts = [
            subject.strip(),
            body.strip(),
        ]

        return "\n".join(
            part
            for part in parts
            if part
        )

    @staticmethod
    def _class_probability(
        probabilities: np.ndarray,
        classes: list[int],
        target_class: int,
    ) -> float:
        """Safely obtain a class probability."""

        for index, class_value in enumerate(classes):
            if int(class_value) == target_class:
                return float(probabilities[index])

        return 0.0

    def _extract_text_features(
        self,
        text: str,
    ) -> list[str]:
        """Extract interpretable suspicious-language features."""

        normalized = text.lower()

        features: list[str] = []

        for term in self._SUSPICIOUS_TERMS:
            if term in normalized:
                features.append(term)

        return features

    def _extract_structural_features(
        self,
        *,
        urls: list[str],
        domains: list[str],
    ) -> list[str]:
        """
        Extract URL/domain characteristics.

        These features do not require a threat-intelligence database.
        Therefore, a previously unseen URL can still produce evidence.
        """

        features: list[str] = []

        for url in urls:
            normalized = url.lower()

            if not normalized.startswith(
                "https://"
            ):
                features.append(
                    "non_https_url"
                )

            if "@" in normalized:
                features.append(
                    "url_userinfo"
                )

            if len(normalized) > 120:
                features.append(
                    "long_url"
                )

            if normalized.count(".") >= 4:
                features.append(
                    "deep_subdomain"
                )

            if any(
                term in normalized
                for term in self._URL_TERMS
            ):
                features.append(
                    "suspicious_url_keyword"
                )

            if self._looks_like_ip_url(
                normalized
            ):
                features.append(
                    "ip_based_url"
                )

            if any(
                shortener in normalized
                for shortener in self._SHORTENERS
            ):
                features.append(
                    "url_shortener"
                )

        for domain in domains:
            normalized = domain.lower().rstrip(".")

            if len(normalized) > 50:
                features.append(
                    "long_domain"
                )

            if normalized.count(".") >= 4:
                features.append(
                    "deep_domain"
                )

            if any(
                term in normalized
                for term in self._URL_TERMS
            ):
                features.append(
                    "suspicious_domain_keyword"
                )

        return list(
            dict.fromkeys(features)
        )

    @staticmethod
    def _looks_like_ip_url(
        url: str,
    ) -> bool:
        """Determine whether a URL contains an IPv4 host."""

        from urllib.parse import urlparse

        try:
            hostname = urlparse(url).hostname
        except ValueError:
            return False

        if not hostname:
            return False

        parts = hostname.split(".")

        if len(parts) != 4:
            return False

        return all(
            part.isdigit()
            and 0 <= int(part) <= 255
            for part in parts
        )

    @staticmethod
    def _confidence(
        probability: float,
        *,
        text_features: list[str],
        structural_features: list[str],
    ) -> float:
        """
        Estimate evidence confidence.

        Confidence is separate from phishing probability. Structural
        corroboration can increase confidence without implying attribution.
        """

        distance = abs(
            probability - 0.5
        ) * 2.0

        corroboration = min(
            0.25,
            (
                len(text_features)
                + len(structural_features)
            )
            * 0.025,
        )

        return min(
            1.0,
            distance + corroboration,
        )


__all__ = [
    "MLPhishingAnalyzer",
    "MLPhishingResult",
    "MODEL_VERSION",
]