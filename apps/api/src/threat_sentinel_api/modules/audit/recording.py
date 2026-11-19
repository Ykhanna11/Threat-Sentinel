from collections.abc import Callable
from contextlib import AbstractContextManager
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_sentinel_api.db.session import unit_of_work
from threat_sentinel_api.modules.audit.service import AuditService
from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.tenants.enums import MembershipStatus, OrganizationStatus
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership

UnitOfWorkFactory = Callable[[], AbstractContextManager[Session]]


def record_failure_event(
    principal: AuthenticatedPrincipal,
    action: str,
    reason: str,
    *,
    organization_id: UUID | None = None,
    target_type: str | None = None,
    target_id: UUID | None = None,
    unit_of_work_factory: UnitOfWorkFactory | None = None,
) -> None:
    open_unit_of_work = unit_of_work_factory or (lambda: unit_of_work())
    with open_unit_of_work() as session:
        recorded_organization_id = None
        if organization_id is not None:
            recorded_organization_id = session.scalar(
                select(Organization.id)
                .join(
                    OrganizationMembership,
                    OrganizationMembership.organization_id == Organization.id,
                )
                .join(User, User.id == OrganizationMembership.user_id)
                .join(ExternalIdentity, ExternalIdentity.user_id == User.id)
                .where(
                    Organization.id == organization_id,
                    Organization.status == OrganizationStatus.ACTIVE,
                    OrganizationMembership.user_id == principal.user_id,
                    OrganizationMembership.status == MembershipStatus.ACTIVE,
                    User.status == UserStatus.ACTIVE,
                    ExternalIdentity.id == principal.external_identity_id,
                    ExternalIdentity.issuer == principal.issuer,
                    ExternalIdentity.subject == principal.subject,
                )
            )
        AuditService(session).record(
            action=action,
            actor_user_id=principal.user_id,
            organization_id=recorded_organization_id,
            target_type=target_type,
            target_id=target_id,
            outcome="failure",
            details={"reason": reason},
        )
