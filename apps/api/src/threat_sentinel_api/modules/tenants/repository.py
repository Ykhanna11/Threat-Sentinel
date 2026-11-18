from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_sentinel_api.db.authorization_locks import (
    lock_membership_by_id_for_share,
    lock_membership_for_share,
    lock_organizations_for_share,
    lock_organization_for_share,
)
from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
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

    def lock_active_user_for_organization_creation(self, issuer: str, subject: str) -> User | None:
        user = IdentityRepository(self._session).lock_user_for_organization_creation(
            issuer,
            subject,
        )
        if user is None or user.status is not UserStatus.ACTIVE:
            return None
        return user

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
        locked_identity = IdentityRepository(self._session).lock_user_for_identity_share(
            issuer,
            subject,
        )
        if locked_identity is None:
            return None
        _, user = locked_identity
        organization = lock_organization_for_share(self._session, organization_id)
        if organization is None:
            return None
        membership = lock_membership_for_share(self._session, user.id, organization_id)
        if (
            user.status is not UserStatus.ACTIVE
            or organization.status is not OrganizationStatus.ACTIVE
            or membership is None
            or membership.status is not MembershipStatus.ACTIVE
        ):
            return None
        return membership

    def list_active_for_identity(self, issuer: str, subject: str) -> list[Organization]:
        locked_identity = IdentityRepository(self._session).lock_user_for_identity_share(
            issuer,
            subject,
        )
        if locked_identity is None:
            return []
        _, user = locked_identity
        if user.status is not UserStatus.ACTIVE:
            return []

        membership_rows = self._session.execute(
            select(OrganizationMembership.id, OrganizationMembership.organization_id)
            .where(OrganizationMembership.user_id == user.id)
            .order_by(OrganizationMembership.id)
        ).all()
        organizations = lock_organizations_for_share(
            self._session,
            (organization_id for _, organization_id in membership_rows),
        )
        organizations_by_id = {organization.id: organization for organization in organizations}

        memberships = [
            membership
            for membership_id, _ in sorted(membership_rows, key=lambda row: row[0])
            if (
                membership := lock_membership_by_id_for_share(
                    self._session,
                    membership_id,
                    user.id,
                )
            )
            is not None
        ]
        return sorted(
            {
                organizations_by_id[membership.organization_id]
                for membership in memberships
                if membership.status is MembershipStatus.ACTIVE
                and membership.organization_id in organizations_by_id
                and organizations_by_id[membership.organization_id].status
                is OrganizationStatus.ACTIVE
            },
            key=lambda organization: (organization.name, organization.id),
        )
