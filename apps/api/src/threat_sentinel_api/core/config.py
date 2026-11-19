import re
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import AnyHttpUrl, Field, SecretStr, TypeAdapter, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPOSITORY_ROOT = Path(__file__).resolve().parents[5]
HTTP_URL_ADAPTER = TypeAdapter(AnyHttpUrl)

JwtSigningAlgorithm = Literal[
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
]


class Settings(BaseSettings):
    app_env: Literal["development", "test", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    cors_origins: list[str] = Field(default_factory=list)
    database_url: SecretStr | None = None
    auth_expected_issuer: str | None = Field(default=None, max_length=512)
    auth_expected_audience: str | None = Field(default=None, max_length=512)
    auth_trusted_jwks_url: str | None = Field(default=None, max_length=2048)
    auth_allowed_jwt_algorithms: list[JwtSigningAlgorithm] | None = None
    auth_clock_skew_seconds: int = Field(default=30, ge=0, le=120)
    auth_jwks_cache_ttl_seconds: int = Field(default=300, ge=1, le=3600)
    auth_jwks_cache_max_entries: int = Field(default=16, ge=1, le=100)
    sensitive_rate_limit_requests: int = Field(default=30, ge=1, le=1000)
    sensitive_rate_limit_window_seconds: int = Field(default=60, ge=1, le=3600)

    model_config = SettingsConfigDict(
        env_file=REPOSITORY_ROOT / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("auth_expected_issuer", "auth_trusted_jwks_url")
    @classmethod
    def validate_auth_https_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value or value != value.strip():
            raise ValueError("URL must not be blank or have surrounding whitespace")
        if re.search(r"%(?![0-9A-Fa-f]{2})", value):
            raise ValueError("URL contains an invalid percent-encoding")

        try:
            HTTP_URL_ADAPTER.validate_python(value)
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("URL is malformed") from exc

        if port is not None and not 1 <= port <= 65535:
            raise ValueError("URL port is out of range")
        if parsed.scheme.lower() != "https" or parsed.hostname is None:
            raise ValueError("URL must be an absolute HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL must not contain user information")
        if "?" in value or "#" in value or parsed.netloc.endswith(":"):
            raise ValueError("URL must not contain a query, fragment, or empty port")
        return value

    @field_validator("auth_expected_audience")
    @classmethod
    def validate_auth_audience(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or value != value.strip()):
            raise ValueError("Audience must not be blank or have surrounding whitespace")
        return value

    @field_validator("auth_allowed_jwt_algorithms")
    @classmethod
    def validate_auth_algorithms(
        cls,
        value: list[JwtSigningAlgorithm] | None,
    ) -> list[JwtSigningAlgorithm] | None:
        if value is not None and not value:
            raise ValueError("At least one JWT signing algorithm must be allowed")
        if value is not None and len(set(value)) != len(value):
            raise ValueError("JWT signing algorithms must not contain duplicates")
        return value

    @property
    def authentication_configured(self) -> bool:
        """Return whether the all-or-none trusted authentication configuration is present."""
        return self.auth_expected_issuer is not None

    @model_validator(mode="after")
    def require_complete_auth_configuration(self) -> "Settings":
        auth_values = (
            self.auth_expected_issuer,
            self.auth_expected_audience,
            self.auth_trusted_jwks_url,
            self.auth_allowed_jwt_algorithms,
        )
        if any(value is not None for value in auth_values) and any(
            value is None for value in auth_values
        ):
            raise ValueError(
                "Authentication issuer, audience, JWKS URL, and algorithms must be "
                "configured together"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
