from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_sentinel_api.modules.audit.context import request_id_context
from threat_sentinel_api.modules.audit.models import SecurityAuditEvent


class AuditService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def record(
        self,
        *,
        action: str,
        actor_user_id: UUID | None = None,
        organization_id: UUID | None = None,
        target_type: str | None = None,
        target_id: UUID | None = None,
        outcome: str = "success",
        request_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> SecurityAuditEvent:
        event = SecurityAuditEvent(
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            action=action,
            outcome=outcome,
            target_type=target_type,
            target_id=target_id,
            request_id=request_id or request_id_context.get(),
            details=details,
        )
        self._session.add(event)
        self._session.flush()
        return event

    def list_organization_events(
        self,
        organization_id: UUID,
        *,
        limit: int = 100,
    ) -> list[SecurityAuditEvent]:
        return list(
            self._session.scalars(
                select(SecurityAuditEvent)
                .where(SecurityAuditEvent.organization_id == organization_id)
                .order_by(SecurityAuditEvent.created_at.desc(), SecurityAuditEvent.id.desc())
                .limit(limit)
            ).all()
        )
