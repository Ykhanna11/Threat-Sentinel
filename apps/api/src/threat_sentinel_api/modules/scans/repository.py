from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_sentinel_api.modules.scans.models import SecurityScan


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def find_personal_by_id(self, scan_id: UUID, owner_user_id: UUID) -> SecurityScan | None:
        if owner_user_id is None:
            raise ValueError("owner_user_id is required")
        statement = select(SecurityScan).where(
            SecurityScan.id == scan_id,
            SecurityScan.owner_user_id == owner_user_id,
        )
        return self._session.scalar(statement)

    def list_personal_for_owner(self, owner_user_id: UUID) -> list[SecurityScan]:
        if owner_user_id is None:
            raise ValueError("owner_user_id is required")
        statement = (
            select(SecurityScan)
            .where(SecurityScan.owner_user_id == owner_user_id)
            .order_by(SecurityScan.created_at, SecurityScan.id)
        )
        return list(self._session.scalars(statement).all())

    def find_organization_by_id(
        self,
        scan_id: UUID,
        organization_id: UUID,
    ) -> SecurityScan | None:
        if organization_id is None:
            raise ValueError("organization_id is required")
        statement = select(SecurityScan).where(
            SecurityScan.id == scan_id,
            SecurityScan.organization_id == organization_id,
        )
        return self._session.scalar(statement)

    def list_organization_for(self, organization_id: UUID) -> list[SecurityScan]:
        if organization_id is None:
            raise ValueError("organization_id is required")
        statement = (
            select(SecurityScan)
            .where(SecurityScan.organization_id == organization_id)
            .order_by(SecurityScan.created_at, SecurityScan.id)
        )
        return list(self._session.scalars(statement).all())

    def add(self, scan: SecurityScan) -> None:
        self._session.add(scan)
        self._session.flush()
