from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.tenants.enums import (
    MembershipStatus,
    OrganizationRole,
    OrganizationStatus,
)
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership
from threat_sentinel_api.modules.tenants.schemas import OrganizationCreate


class OrganizationRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def find_active_user(self, issuer: str, subject: str) -> User | None:
        statement = (
            select(User)
            .join(User.identities)
            .where(
                ExternalIdentity.issuer == issuer,
                ExternalIdentity.subject == subject,
                User.status == UserStatus.ACTIVE,
            )
        )
        return self._session.scalar(statement)

    def create_with_owner(
        self,
        details: OrganizationCreate,
        owner: User,
    ) -> Organization:
        organization = Organization(
            name=details.name,
            slug=details.slug,
            created_by=owner,
        )
        self._session.add(organization)
        self._session.flush()

        self._session.add(
            OrganizationMembership(
                organization=organization,
                user=owner,
                role=OrganizationRole.OWNER,
                status=MembershipStatus.ACTIVE,
            )
        )
        self._session.flush()
        return organization

    def find_active_membership(
        self,
        organization_id: UUID,
        issuer: str,
        subject: str,
    ) -> OrganizationMembership | None:
        statement = (
            select(OrganizationMembership)
            .join(OrganizationMembership.organization)
            .join(OrganizationMembership.user)
            .join(User.identities)
            .options(joinedload(OrganizationMembership.organization))
            .where(
                OrganizationMembership.organization_id == organization_id,
                ExternalIdentity.issuer == issuer,
                ExternalIdentity.subject == subject,
                OrganizationMembership.status == MembershipStatus.ACTIVE,
                Organization.status == OrganizationStatus.ACTIVE,
                User.status == UserStatus.ACTIVE,
            )
        )
        return self._session.scalar(statement)

    def list_active_for_identity(self, issuer: str, subject: str) -> list[Organization]:
        statement = (
            select(Organization)
            .join(Organization.memberships)
            .join(OrganizationMembership.user)
            .join(User.identities)
            .where(
                ExternalIdentity.issuer == issuer,
                ExternalIdentity.subject == subject,
                OrganizationMembership.status == MembershipStatus.ACTIVE,
                Organization.status == OrganizationStatus.ACTIVE,
                User.status == UserStatus.ACTIVE,
            )
            .order_by(Organization.name, Organization.id)
        )
        return list(self._session.scalars(statement).all())
