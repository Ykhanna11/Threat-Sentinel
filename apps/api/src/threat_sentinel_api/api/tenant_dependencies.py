from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from threat_sentinel_api.api.dependencies import get_current_principal
from threat_sentinel_api.db.session import unit_of_work
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.tenants.authorization import (
    OrganizationScanAction,
    allows_organization_scan_action,
)
from threat_sentinel_api.modules.tenants.context import ActiveOrganizationContext
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.service import (
    OrganizationAccessDenied,
    OrganizationService,
)

OrganizationServiceFactory = Callable[[Session], OrganizationService]


def get_organization_service_factory() -> OrganizationServiceFactory:
    """Provide an overridable factory for services bound to the check transaction."""
    return lambda session: OrganizationService(OrganizationRepository(session))


def get_active_organization_context(
    organization_id: Annotated[UUID, Path()],
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    service_factory: Annotated[
        OrganizationServiceFactory,
        Depends(get_organization_service_factory),
    ],
) -> ActiveOrganizationContext:
    """Authorize one organization against local membership for the current principal."""
    try:
        with unit_of_work() as session:
            membership = service_factory(session).require_active_membership(
                principal,
                organization_id,
            )
            context = ActiveOrganizationContext(
                principal=principal,
                organization_id=organization_id,
                membership_id=membership.id,
            )
    except OrganizationAccessDenied:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
        ) from None

    return context


def require_organization_scan_action(
    action: OrganizationScanAction,
) -> Callable[..., ActiveOrganizationContext]:
    """Build a dependency requiring active local membership and the requested scan action."""

    def dependency(
        organization_id: Annotated[UUID, Path()],
        principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
        service_factory: Annotated[
            OrganizationServiceFactory,
            Depends(get_organization_service_factory),
        ],
    ) -> ActiveOrganizationContext:
        try:
            with unit_of_work() as session:
                membership = service_factory(session).require_active_membership(
                    principal,
                    organization_id,
                )
                if not allows_organization_scan_action(membership.role, action):
                    raise OrganizationAccessDenied(
                        "The user is not authorized for this organization scan action."
                    )
                context = ActiveOrganizationContext(
                    principal=principal,
                    organization_id=organization_id,
                    membership_id=membership.id,
                )
        except OrganizationAccessDenied:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
            ) from None

        return context

    return dependency
