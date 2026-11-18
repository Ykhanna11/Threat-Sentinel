from uuid import UUID

from threat_sentinel_api.modules.identity.schemas import VerifiedUserContext
from threat_sentinel_api.modules.identity.service import InvalidPrincipalError
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.schemas import OrganizationCreate


class ActiveUserRequired(InvalidPrincipalError):
    """Raised when an inactive or unknown user attempts an organization operation."""


class OrganizationAccessDenied(PermissionError):
    """Compatibility base for organization scope and action denials."""


class OrganizationConflict(RuntimeError):
    """Raised when an organization lifecycle operation conflicts with existing state."""


class OrganizationScopeUnavailable(OrganizationAccessDenied):
    """Raised when the requested organization scope is missing or inaccessible."""


class OrganizationPermissionDenied(OrganizationAccessDenied):
    """Raised when an active organization member lacks permission for an action."""


class OrganizationService:
    def __init__(self, repository: OrganizationRepository) -> None:
        self._repository = repository

    def create_organization(
        self,
        principal: VerifiedUserContext,
        details: OrganizationCreate,
    ) -> Organization:
        """Create the organization and initial owner membership in the caller's UOW."""
        owner = self._repository.lock_active_user_for_organization_creation(
            principal.issuer,
            principal.subject,
        )
        if owner is None:
            raise ActiveUserRequired("An active local user is required.")
        if self._repository.slug_exists(details.slug):
            raise OrganizationConflict("An organization with that slug already exists.")
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
            principal,
        )
        if membership is None:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        return membership
