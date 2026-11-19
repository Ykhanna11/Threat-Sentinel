from sqlalchemy.orm import Session

from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.audit.service import AuditService
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.identity.service import InactiveUserError
from threat_sentinel_api.modules.tenants.enums import MembershipStatus, OrganizationRole
from threat_sentinel_api.modules.tenants.invariants import ActiveOwnerRetentionError
from threat_sentinel_api.modules.tenants.lifecycle_repository import (
    OrganizationLifecycleRepository,
)


class AccountLifecycleConflict(RuntimeError):
    """Raised when an account lifecycle transition is not valid for the current state."""


class AccountLifecycleService:
    def __init__(self, session: Session) -> None:
        self._identity_repository = IdentityRepository(session)
        self._organization_repository = OrganizationLifecycleRepository(session)
        self._audit = AuditService(session)

    def deactivate(self, principal: AuthenticatedPrincipal) -> None:
        user = self._identity_repository.lock_user_for_principal_update(principal)
        if user is None:
            raise InactiveUserError("The linked account is not active.")
        if user.status is not UserStatus.ACTIVE:
            raise AccountLifecycleConflict(
                "The account cannot be deactivated from its current state."
            )

        organization_ids = tuple(
            self._organization_repository.find_active_owner_organization_ids(user.id)
        )
        organizations = self._organization_repository.lock_organizations_for_update(
            organization_ids
        )
        if {organization.id for organization in organizations} != set(organization_ids):
            raise AccountLifecycleConflict("The account lifecycle state could not be updated.")

        memberships = self._organization_repository.lock_memberships_for_organizations_for_update(
            organization_ids
        )
        for organization_id in organization_ids:
            if not any(
                membership.organization_id == organization_id
                and membership.user_id == user.id
                and membership.role is OrganizationRole.OWNER
                and membership.status is MembershipStatus.ACTIVE
                for membership in memberships
            ) or not self._organization_repository.has_other_active_owner(
                organization_id,
                user.id,
            ):
                raise ActiveOwnerRetentionError(
                    "An organization must retain at least one active owner."
                )

        user.status = UserStatus.DEACTIVATED
        self._identity_repository.flush()
        self._audit.record(
            action="account.deactivated",
            actor_user_id=user.id,
            target_type="user",
            target_id=user.id,
        )
