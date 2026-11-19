from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator, model_validator

from threat_sentinel_api.modules.tenants.enums import (
    MembershipStatus,
    OrganizationRole,
    OrganizationStatus,
)


class OrganizationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
    )

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("name must not be blank")
        return normalized


class OrganizationUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    name: Annotated[StrictStr, Field(min_length=1, max_length=200)] | None = None
    slug: (
        Annotated[
            StrictStr,
            Field(min_length=1, max_length=100, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$"),
        ]
        | None
    ) = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("name must not be blank")
        return normalized

    @model_validator(mode="after")
    def require_change(self) -> "OrganizationUpdate":
        if not any(value is not None for value in (self.name, self.slug)):
            raise ValueError("at least one field must be provided")
        return self


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    name: str
    slug: str
    status: OrganizationStatus
    created_at: datetime


class OrganizationMemberResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    membership_id: UUID
    display_name: str | None
    role: OrganizationRole
    status: MembershipStatus
    created_at: datetime


class MembershipUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: OrganizationRole | None = None
    status: MembershipStatus | None = None

    @model_validator(mode="after")
    def require_change(self) -> "MembershipUpdate":
        if self.role is None and self.status is None:
            raise ValueError("at least one field must be provided")
        return self


class OwnershipTransfer(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    membership_id: UUID


class InvitationCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    email: Annotated[StrictStr, Field(min_length=3, max_length=320)]
    role: OrganizationRole

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if (
            not normalized
            or any(character.isspace() for character in normalized)
            or normalized.count("@") != 1
            or "." not in normalized.rsplit("@", 1)[-1]
        ):
            raise ValueError("email is invalid")
        return normalized

    @field_validator("role")
    @classmethod
    def reject_owner_role(cls, value: OrganizationRole) -> OrganizationRole:
        if value is OrganizationRole.OWNER:
            raise ValueError("owner must be granted by ownership transfer")
        return value


class InvitationAccept(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    token: Annotated[
        StrictStr,
        Field(min_length=32, max_length=128, pattern=r"^[A-Za-z0-9_-]+$"),
    ]


class InvitationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    intended_email: str
    role: OrganizationRole
    expires_at: datetime
    token: str


class MembershipAcceptanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    organization_id: UUID
    role: OrganizationRole
    status: MembershipStatus


class SecurityAuditEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    created_at: datetime
    actor_user_id: UUID | None
    organization_id: UUID | None
    action: str
    outcome: str
    target_type: str | None
    target_id: UUID | None
    request_id: str | None
