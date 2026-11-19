from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, JSON, String, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column

from threat_sentinel_api.db.base import Base
from threat_sentinel_api.db.mixins import UUIDPrimaryKeyMixin


class SecurityAuditEvent(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "security_audit_events"
    __table_args__ = (
        CheckConstraint("length(trim(action)) > 0", name="ck_security_audit_action_not_blank"),
        CheckConstraint(
            "outcome IN ('success', 'failure')",
            name="ck_security_audit_outcome",
        ),
        Index("ix_security_audit_events_actor_created", "actor_user_id", "created_at"),
        Index(
            "ix_security_audit_events_org_created",
            "organization_id",
            "created_at",
        ),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    actor_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    organization_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("organizations.id", ondelete="SET NULL"),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    outcome: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        server_default=text("'success'"),
    )
    target_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    target_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
