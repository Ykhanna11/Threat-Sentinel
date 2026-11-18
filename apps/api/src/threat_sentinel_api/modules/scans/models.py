from uuid import UUID

from sqlalchemy import CheckConstraint, ForeignKey, Index, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from threat_sentinel_api.db.base import Base
from threat_sentinel_api.db.mixins import TimestampMixin, UUIDPrimaryKeyMixin
from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.tenants.models import Organization


class SecurityScan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "security_scans"
    __table_args__ = (
        CheckConstraint(
            "(owner_user_id IS NOT NULL AND organization_id IS NULL) OR "
            "(owner_user_id IS NULL AND organization_id IS NOT NULL)",
            name="ck_security_scans_exactly_one_scope",
        ),
        CheckConstraint(
            "organization_id IS NOT NULL OR owner_user_id = created_by_user_id",
            name="ck_security_scans_personal_owner_is_creator",
        ),
        Index("ix_security_scans_owner_created_at", "owner_user_id", "created_at"),
        Index("ix_security_scans_organization_created_at", "organization_id", "created_at"),
    )

    owner_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=True,
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )

    owner_user: Mapped[User | None] = relationship(foreign_keys=[owner_user_id])
    organization: Mapped[Organization | None] = relationship(foreign_keys=[organization_id])
    created_by: Mapped[User] = relationship(foreign_keys=[created_by_user_id])
