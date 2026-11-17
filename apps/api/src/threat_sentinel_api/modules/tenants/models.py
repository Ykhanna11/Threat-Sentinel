from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    Uuid,
    literal_column,
    text,
)
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql.compiler import SQLCompiler
from sqlalchemy.sql.functions import FunctionElement

from threat_sentinel_api.db.base import Base
from threat_sentinel_api.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from threat_sentinel_api.db.types import enum_values
from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.tenants.enums import (
    InvitationStatus,
    MembershipStatus,
    OrganizationRole,
    OrganizationStatus,
)


class NormalizedInvitationEmail(FunctionElement[str]):
    type = String()
    inherit_cache = True


@compiles(NormalizedInvitationEmail)
def _compile_normalized_invitation_email(
    element: NormalizedInvitationEmail,
    compiler: SQLCompiler,
    **kwargs: Any,
) -> str:
    return f"lower(trim({compiler.process(element.clauses, **kwargs)}))"


@compiles(NormalizedInvitationEmail, "postgresql")
def _compile_postgresql_normalized_invitation_email(
    element: NormalizedInvitationEmail,
    compiler: SQLCompiler,
    **kwargs: Any,
) -> str:
    return f"lower(TRIM(BOTH FROM {compiler.process(element.clauses, **kwargs)}))"


class Organization(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "organizations"
    __table_args__ = (
        UniqueConstraint("slug", name="uq_organizations_slug"),
        CheckConstraint("length(trim(name)) > 0", name="ck_organizations_name_not_blank"),
        CheckConstraint("slug = lower(slug)", name="ck_organizations_slug_lowercase"),
        Index("ix_organizations_status", "status"),
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[OrganizationStatus] = mapped_column(
        Enum(
            OrganizationStatus,
            name="organization_status",
            native_enum=False,
            create_constraint=True,
            validate_strings=True,
            values_callable=enum_values,
        ),
        nullable=False,
        default=OrganizationStatus.ACTIVE,
        server_default=text("'active'"),
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )

    created_by: Mapped[User] = relationship(foreign_keys=[created_by_user_id])
    memberships: Mapped[list["OrganizationMembership"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
        passive_deletes=True,
        foreign_keys="OrganizationMembership.organization_id",
    )
    invitations: Mapped[list["OrganizationInvitation"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
        passive_deletes=True,
        foreign_keys="OrganizationInvitation.organization_id",
    )


class OrganizationMembership(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "organization_memberships"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "user_id",
            name="uq_organization_memberships_organization_user",
        ),
        UniqueConstraint(
            "organization_id",
            "id",
            name="uq_organization_memberships_organization_id",
        ),
        Index("ix_organization_memberships_user_status", "user_id", "status"),
        Index(
            "ix_organization_memberships_organization_status_role",
            "organization_id",
            "status",
            "role",
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    role: Mapped[OrganizationRole] = mapped_column(
        Enum(
            OrganizationRole,
            name="organization_role",
            native_enum=False,
            create_constraint=True,
            validate_strings=True,
            values_callable=enum_values,
        ),
        nullable=False,
    )
    status: Mapped[MembershipStatus] = mapped_column(
        Enum(
            MembershipStatus,
            name="membership_status",
            native_enum=False,
            create_constraint=True,
            validate_strings=True,
            values_callable=enum_values,
        ),
        nullable=False,
        default=MembershipStatus.ACTIVE,
        server_default=text("'active'"),
    )

    organization: Mapped[Organization] = relationship(
        back_populates="memberships",
        foreign_keys=[organization_id],
    )
    user: Mapped[User] = relationship(foreign_keys=[user_id])


class OrganizationInvitation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "organization_invitations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "accepted_membership_id"],
            ["organization_memberships.organization_id", "organization_memberships.id"],
            name="fk_org_invitations_membership_same_org",
        ),
        UniqueConstraint(
            "accepted_membership_id",
            name="uq_organization_invitations_accepted_membership",
        ),
        CheckConstraint(
            "length(trim(intended_email)) > 0",
            name="ck_organization_invitations_email_not_blank",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="ck_organization_invitations_expiration_after_creation",
        ),
        CheckConstraint(
            "status != 'accepted' OR "
            "(accepted_membership_id IS NOT NULL AND accepted_at IS NOT NULL)",
            name="ck_organization_invitations_accepted_relationship",
        ),
        CheckConstraint(
            "status != 'revoked' OR revoked_at IS NOT NULL",
            name="ck_organization_invitations_revoked_timestamp",
        ),
        Index("ix_organization_invitations_organization_status", "organization_id", "status"),
        Index("ix_organization_invitations_expires_at", "expires_at"),
        Index(
            "uq_organization_invitations_pending_normalized_email",
            "organization_id",
            NormalizedInvitationEmail(literal_column("intended_email")),
            unique=True,
            postgresql_where=text("status = 'pending'"),
            sqlite_where=text("status = 'pending'"),
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    inviter_user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    intended_email: Mapped[str] = mapped_column(String(320), nullable=False)
    status: Mapped[InvitationStatus] = mapped_column(
        Enum(
            InvitationStatus,
            name="invitation_status",
            native_enum=False,
            create_constraint=True,
            validate_strings=True,
            values_callable=enum_values,
        ),
        nullable=False,
        default=InvitationStatus.PENDING,
        server_default=text("'pending'"),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    accepted_membership_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        nullable=True,
    )

    organization: Mapped[Organization] = relationship(
        back_populates="invitations",
        foreign_keys=[organization_id],
    )
    inviter: Mapped[User] = relationship(foreign_keys=[inviter_user_id])
    accepted_membership: Mapped[OrganizationMembership | None] = relationship(
        primaryjoin=(
            "and_(OrganizationInvitation.organization_id == "
            "OrganizationMembership.organization_id, "
            "OrganizationInvitation.accepted_membership_id == OrganizationMembership.id)"
        ),
        foreign_keys=[accepted_membership_id],
        uselist=False,
    )
