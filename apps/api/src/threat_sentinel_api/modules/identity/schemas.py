from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class VerifiedUserContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    issuer: str = Field(min_length=1, max_length=512)
    subject: str = Field(min_length=1, max_length=512)
    email: str | None = Field(default=None, max_length=320)
    email_verified: bool = False

    @field_validator("issuer", "subject")
    @classmethod
    def reject_blank_identifiers(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

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
