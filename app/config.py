"""
Sentinel AI
Application Configuration

Centralized, environment-driven configuration for the platform.

Security principles:
- No secrets are hard-coded.
- External intelligence is optional.
- Network operations have bounded timeouts.
- Uploaded email size is limited.
- Attachment size and count are limited.
- Analysis remains usable when external providers fail.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "Sentinel AI"
    app_version: str = "2.0.0"
    environment: str = Field(default="development")
    debug: bool = False

    # HTTP server
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)

    # Database
    database_url: str = "sqlite:///./runtime/sentinel.db"

    # Upload security limits
    max_email_size_mb: int = Field(default=25, ge=1, le=100)
    max_attachment_size_mb: int = Field(default=15, ge=1, le=50)
    max_attachment_count: int = Field(default=25, ge=1, le=100)

    # Parsing / extraction limits
    max_body_chars: int = Field(default=1_000_000, ge=10_000)
    max_html_chars: int = Field(default=2_000_000, ge=10_000)
    max_headers: int = Field(default=500, ge=50)
    max_urls: int = Field(default=500, ge=10)
    max_ips: int = Field(default=500, ge=10)
    max_domains: int = Field(default=500, ge=10)
    max_entities: int = Field(default=1_000, ge=10)

    # Analysis safety
    analysis_timeout_seconds: float = Field(
        default=30.0,
        gt=0.0,
        le=300.0,
    )
    provider_timeout_seconds: float = Field(
        default=4.0,
        gt=0.0,
        le=30.0,
    )
    provider_connect_timeout_seconds: float = Field(
        default=2.0,
        gt=0.0,
        le=15.0,
    )
    dns_timeout_seconds: float = Field(
        default=3.0,
        gt=0.0,
        le=30.0,
    )
    max_provider_retries: int = Field(
        default=1,
        ge=0,
        le=3,
    )

    # External intelligence
    enable_external_intelligence: bool = False
    enable_dns_intelligence: bool = True
    enable_urlscan: bool = False
    enable_virustotal: bool = False
    enable_geoip: bool = False
    enable_company_intelligence: bool = False

    # Provider credentials
    virustotal_api_key: str = ""
    urlscan_api_key: str = ""

    # Provider endpoints
    virustotal_base_url: str = "https://www.virustotal.com/api/v3"
    urlscan_base_url: str = "https://urlscan.io/api/v1"

    # Caching
    intelligence_cache_ttl_seconds: int = Field(
        default=3600,
        ge=60,
        le=604800,
    )

    # Evidence / forensic settings
    preserve_evidence_hash: bool = True
    hash_algorithm: str = "sha256"
    persist_raw_email: bool = False

    # Logging
    log_level: str = "INFO"
    audit_log_enabled: bool = True

    # CORS
    cors_origins: str = (
        "http://127.0.0.1:8000,http://localhost:8000"
    )

    @property
    def max_email_size_bytes(self) -> int:
        """Maximum accepted email upload size in bytes."""
        return self.max_email_size_mb * 1024 * 1024

    @property
    def max_attachment_size_bytes(self) -> int:
        """Maximum accepted individual attachment size in bytes."""
        return self.max_attachment_size_mb * 1024 * 1024

    @property
    def allowed_cors_origins(self) -> list[str]:
        """Return configured CORS origins as a normalized list."""
        return [
            origin.strip()
            for origin in self.cors_origins.split(",")
            if origin.strip()
        ]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return the singleton application settings object.

    Caching prevents repeated environment parsing and guarantees that
    all components use the same configuration instance.
    """
    return Settings()


settings = get_settings()


__all__ = [
    "Settings",
    "get_settings",
    "settings",
]