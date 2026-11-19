from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from threat_sentinel_api.db.authorization_locks import (
    lock_invitation_by_id_for_no_key_update,
    lock_invitations_for_no_key_update,
    lock_membership_by_id_for_no_key_update,
    lock_membership_by_id_for_share,
    lock_memberships_for_no_key_update,
    lock_organization_for_no_key_update,
    lock_organization_for_share,
    lock_user_for_share,
    lock_users_for_no_key_update,
)
from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.identity.service import InvalidPrincipalError
from threat_sentinel_api.modules.tenants.enums import MembershipStatus, OrganizationRole
from threat_sentinel_api.modules.tenants.models import (
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
)


class OrganizationLifecycleRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def find_membership_user_id(
        self,
        organization_id: UUID,
        membership_id: UUID,
    ) -> UUID | None:
        return self._session.scalar(
            select(OrganizationMembership.user_id).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.id == membership_id,
            )
        )

    def find_active_owner_organization_ids(self, user_id: UUID) -> list[UUID]:
        return list(
            self._session.scalars(
                select(OrganizationMembership.organization_id)
                .where(
                    OrganizationMembership.user_id == user_id,
                    OrganizationMembership.role == OrganizationRole.OWNER,
                    OrganizationMembership.status == MembershipStatus.ACTIVE,
                )
                .order_by(OrganizationMembership.organization_id)
            ).all()
        )

    def find_invitation_location(self, token_hash: str) -> tuple[UUID, UUID] | None:
        row = self._session.execute(
            select(OrganizationInvitation.id, OrganizationInvitation.organization_id).where(
                OrganizationInvitation.token_hash == token_hash,
            )
        ).one_or_none()
        return None if row is None else (row[0], row[1])

    def find_verified_identity_for_email(self, email: str) -> tuple[UUID, UUID] | None:
        rows = self._session.execute(
            select(ExternalIdentity.id, ExternalIdentity.user_id).where(
                func.lower(func.trim(ExternalIdentity.email)) == email,
                ExternalIdentity.email_verified_at.is_not(None),
            )
        ).all()
        if len(rows) != 1:
            return None
        return rows[0][0], rows[0][1]

    def is_verified_identity_for_email(
        self,
        identity_id: UUID,
        user_id: UUID,
        email: str,
    ) -> bool:
        return (
            self._session.scalar(
                select(ExternalIdentity.id).where(
                    ExternalIdentity.id == identity_id,
                    ExternalIdentity.user_id == user_id,
                    func.lower(func.trim(ExternalIdentity.email)) == email,
                    ExternalIdentity.email_verified_at.is_not(None),
                )
            )
            is not None
        )

    def lock_principal_user_for_share(
        self,
        principal: AuthenticatedPrincipal,
    ) -> User | None:
        identity = IdentityRepository(self._session)
        link = identity.find_identity_link(principal.issuer, principal.subject)
        if link != (principal.external_identity_id, principal.user_id):
            return None
        user = lock_user_for_share(self._session, principal.user_id)
        if user is None or identity.find_identity_link(principal.issuer, principal.subject) != link:
            return None
        return user

    def lock_principal_users_for_update(
        self,
        principal: AuthenticatedPrincipal,
        additional_user_ids: tuple[UUID, ...] = (),
    ) -> dict[UUID, User]:
        identity = IdentityRepository(self._session)
        link = identity.find_identity_link(principal.issuer, principal.subject)
        if link != (principal.external_identity_id, principal.user_id):
            raise InvalidPrincipalError("The authenticated principal is no longer valid.")
        users = lock_users_for_no_key_update(
            self._session,
            (principal.user_id, *additional_user_ids),
        )
        users_by_id = {user.id: user for user in users}
        if (
            principal.user_id not in users_by_id
            or identity.find_identity_link(principal.issuer, principal.subject) != link
        ):
            raise InvalidPrincipalError("The authenticated principal is no longer valid.")
        return users_by_id

    def lock_organization_for_share(self, organization_id: UUID) -> Organization | None:
        return lock_organization_for_share(self._session, organization_id)

    def lock_organization_for_update(self, organization_id: UUID) -> Organization | None:
        return lock_organization_for_no_key_update(self._session, organization_id)

    def lock_organizations_for_update(
        self,
        organization_ids: tuple[UUID, ...],
    ) -> list[Organization]:
        organizations: list[Organization] = []
        for organization_id in sorted(set(organization_ids)):
            organization = lock_organization_for_no_key_update(self._session, organization_id)
            if organization is not None:
                organizations.append(organization)
        return organizations

    def lock_memberships_for_update(
        self,
        organization_id: UUID,
    ) -> list[OrganizationMembership]:
        return lock_memberships_for_no_key_update(self._session, organization_id)

    def lock_memberships_for_organizations_for_update(
        self,
        organization_ids: tuple[UUID, ...],
    ) -> list[OrganizationMembership]:
        rows = self._session.execute(
            select(OrganizationMembership.id, OrganizationMembership.organization_id)
            .where(OrganizationMembership.organization_id.in_(organization_ids))
            .order_by(OrganizationMembership.id)
        ).all()
        memberships: list[OrganizationMembership] = []
        for membership_id, organization_id in rows:
            membership = lock_membership_by_id_for_no_key_update(
                self._session,
                membership_id,
                organization_id,
            )
            if membership is not None:
                memberships.append(membership)
        return memberships

    def has_other_active_owner(
        self,
        organization_id: UUID,
        excluded_user_id: UUID,
    ) -> bool:
        return (
            self._session.scalar(
                select(OrganizationMembership.id)
                .join(User, User.id == OrganizationMembership.user_id)
                .where(
                    OrganizationMembership.organization_id == organization_id,
                    OrganizationMembership.role == OrganizationRole.OWNER,
                    OrganizationMembership.status == MembershipStatus.ACTIVE,
                    OrganizationMembership.user_id != excluded_user_id,
                    User.status == UserStatus.ACTIVE,
                )
                .limit(1)
            )
            is not None
        )

    def has_active_owner(self, organization_id: UUID) -> bool:
        return (
            self._session.scalar(
                select(OrganizationMembership.id)
                .join(User, User.id == OrganizationMembership.user_id)
                .where(
                    OrganizationMembership.organization_id == organization_id,
                    OrganizationMembership.role == OrganizationRole.OWNER,
                    OrganizationMembership.status == MembershipStatus.ACTIVE,
                    User.status == UserStatus.ACTIVE,
                )
                .limit(1)
            )
            is not None
        )

    def lock_memberships_for_share(
        self,
        organization_id: UUID,
    ) -> list[OrganizationMembership]:
        membership_rows = self._session.execute(
            select(OrganizationMembership.id, OrganizationMembership.user_id)
            .where(OrganizationMembership.organization_id == organization_id)
            .order_by(OrganizationMembership.id)
        ).all()
        memberships: list[OrganizationMembership] = []
        for membership_id, user_id in membership_rows:
            membership = lock_membership_by_id_for_share(
                self._session,
                membership_id,
                user_id,
            )
            if membership is not None:
                memberships.append(membership)
        return memberships

    def lock_invitations_for_update(
        self,
        organization_id: UUID,
    ) -> list[OrganizationInvitation]:
        return lock_invitations_for_no_key_update(self._session, organization_id)

    def lock_invitation_for_update(
        self,
        invitation_id: UUID,
        organization_id: UUID,
    ) -> OrganizationInvitation | None:
        return lock_invitation_by_id_for_no_key_update(
            self._session,
            invitation_id,
            organization_id,
        )

    def lock_membership_for_update(
        self,
        membership_id: UUID,
        organization_id: UUID,
    ) -> OrganizationMembership | None:
        return lock_membership_by_id_for_no_key_update(
            self._session,
            membership_id,
            organization_id,
        )

    def add_invitation(self, invitation: OrganizationInvitation) -> None:
        self._session.add(invitation)
        self._session.flush()
