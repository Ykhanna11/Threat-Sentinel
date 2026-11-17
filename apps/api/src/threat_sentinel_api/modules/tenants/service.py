from uuid import UUID

from threat_sentinel_api.modules.identity.schemas import VerifiedUserContext
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.schemas import OrganizationCreate


class ActiveUserRequired(PermissionError):
    """Raised when an inactive or unknown user attempts an organization operation."""


class OrganizationAccessDenied(PermissionError):
    """Raised when the authenticated user has no active access to an organization."""


class OrganizationService:
    def __init__(self, repository: OrganizationRepository) -> None:
        self._repository = repository

    def create_organization(
        self,
        principal: VerifiedUserContext,
        details: OrganizationCreate,
    ) -> Organization:
        owner = self._repository.find_active_user(principal.issuer, principal.subject)
        if owner is None:
            raise ActiveUserRequired("An active local user is required.")
        return self._repository.create_with_owner(details, owner)

    def list_organizations(self, principal: VerifiedUserContext) -> list[Organization]:
        return self._repository.list_active_for_identity(principal.issuer, principal.subject)

    def require_active_membership(
        self,
        principal: VerifiedUserContext,
        organization_id: UUID,
    ) -> OrganizationMembership:
        membership = self._repository.find_active_membership(
            organization_id,
            principal.issuer,
            principal.subject,
        )
        if membership is None:
            raise OrganizationAccessDenied("The user does not have active organization access.")
        return membership
