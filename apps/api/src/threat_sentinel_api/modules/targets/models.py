from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threat_sentinel_api.db.base import Base
from threat_sentinel_api.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.tenants.models import Organization


class SecurityTarget(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "security_targets"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "hostname",
            name="uq_security_targets_organization_hostname",
        ),
        UniqueConstraint(
            "organization_id",
            "id",
            name="uq_security_targets_organization_id",
        ),
        CheckConstraint(
            "length(hostname) BETWEEN 1 AND 253",
            name="ck_security_targets_hostname_length",
        ),
        Index(
            "ix_security_targets_organization_created",
            "organization_id",
            "created_at",
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    created_by_user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    organization: Mapped[Organization] = relationship()
    created_by: Mapped[User] = relationship()


class TargetVerificationChallenge(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "target_verification_challenges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "target_id"],
            ["security_targets.organization_id", "security_targets.id"],
            name="fk_target_challenges_target_same_organization",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["issued_by_user_id"],
            ["users.id"],
            name="fk_target_challenges_issuer",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("challenge_hash", name="uq_target_challenges_hash"),
        UniqueConstraint(
            "organization_id",
            "target_id",
            name="uq_target_challenges_one_per_target",
        ),
        CheckConstraint(
            "length(challenge_hash) = 64",
            name="ck_target_challenges_hash_length",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="ck_target_challenges_expiry_after_creation",
        ),
        Index(
            "ix_target_challenges_organization_target_expiry",
            "organization_id",
            "target_id",
            "expires_at",
        ),
    )

    organization_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    target_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    issued_by_user_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    challenge_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    target: Mapped[SecurityTarget] = relationship()
    issued_by: Mapped[User] = relationship()
