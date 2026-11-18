from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class VerifiedAccessTokenClaims(BaseModel):
    """Minimal internal claims contract for output from a successful token verifier."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    issuer: str = Field(min_length=1, max_length=512)
    subject: str = Field(min_length=1, max_length=512)
    audiences: tuple[str, ...] = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    not_before: datetime | None = None
    key_id: str | None = Field(default=None, max_length=256)
    email: str | None = Field(default=None, max_length=320)
    email_verified: bool | None = None
    token_type: str | None = Field(default=None, max_length=64)

    @field_validator("issuer", "subject", "audiences")
    @classmethod
    def reject_blank_identifiers(cls, value: str | tuple[str, ...]) -> str | tuple[str, ...]:
        values = value if isinstance(value, tuple) else (value,)
        if any(not identifier.strip() for identifier in values):
            raise ValueError("must not be blank")
        return value

    @field_validator("issued_at", "expires_at", "not_before")
    @classmethod
    def require_timezone_aware_timestamps(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("timestamp must include a timezone")
        return value

    @field_validator("key_id", "token_type")
    @classmethod
    def reject_blank_optional_identifiers(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("must not be blank")
        return value

    @field_validator("email")
    @classmethod
    def normalize_optional_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def validate_claim_relationships(self) -> "VerifiedAccessTokenClaims":
        if self.expires_at <= self.issued_at:
            raise ValueError("expiration must be later than issuance")
        if self.not_before is not None and self.not_before >= self.expires_at:
            raise ValueError("not-before must be earlier than expiration")
        if self.email_verified is True and self.email is None:
            raise ValueError("email cannot be verified when it is absent")
        return self


class VerifiedUserContext(BaseModel):
    """Internal identity-service context; not a credential or proof of verification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer: str = Field(min_length=1, max_length=512)
    subject: str = Field(min_length=1, max_length=512)
    email: str | None = Field(default=None, max_length=320)
    email_verified: bool = False

    @field_validator("issuer", "subject")
    @classmethod
    def reject_blank_identifiers(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must not be blank")
        return value

    @field_validator("email")
    @classmethod
    def normalize_optional_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def verified_email_must_be_present(self) -> "VerifiedUserContext":
        if self.email_verified and self.email is None:
            raise ValueError("email cannot be verified when it is absent")
        return self


class AuthenticatedPrincipal(VerifiedUserContext):
    """Local identity resolved from verified claims; not an authorization grant."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UUID
    external_identity_id: UUID
