from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threat_sentinel_api.api.dependencies import get_current_principal
from threat_sentinel_api.db.session import unit_of_work
from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.identity.service import InvalidPrincipalError
from threat_sentinel_api.modules.tenants.lifecycle_service import (
    InvitationUnavailable,
    OrganizationLifecycleService,
)
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.schemas import (
    InvitationAccept,
    InvitationCreate,
    InvitationResponse,
    MembershipAcceptanceResponse,
    MembershipUpdate,
    OrganizationCreate,
    OrganizationMemberResponse,
    OrganizationResponse,
    OrganizationUpdate,
    OwnershipTransfer,
)
from threat_sentinel_api.modules.tenants.service import (
    OrganizationConflict,
    OrganizationPermissionDenied,
    OrganizationService,
)

router = APIRouter(tags=["organizations"])


def _organization_response(organization: Organization) -> OrganizationResponse:
    return OrganizationResponse(
        id=organization.id,
        name=organization.name,
        slug=organization.slug,
        status=organization.status,
        created_at=organization.created_at,
    )


def _member_response(
    session: Session,
    membership: OrganizationMembership,
) -> OrganizationMemberResponse:
    user = session.get(User, membership.user_id)
    return OrganizationMemberResponse(
        membership_id=membership.id,
        display_name=user.display_name if user is not None else None,
        role=membership.role,
        status=membership.status,
        created_at=membership.created_at,
    )


def _constraint_name(error: IntegrityError) -> str | None:
    diagnostic = getattr(error.orig, "diag", None)
    return getattr(diagnostic, "constraint_name", None)


def _is_organization_slug_conflict(error: IntegrityError) -> bool:
    return _constraint_name(error) == "uq_organizations_slug" or (
        "UNIQUE constraint failed: organizations.slug" in str(error.orig)
    )


def _is_pending_invitation_conflict(error: IntegrityError) -> bool:
    name = _constraint_name(error)
    return name == "uq_organization_invitations_pending_normalized_email" or (
        "uq_organization_invitations_pending_normalized_email" in str(error.orig)
    )


@router.post(
    "/organizations",
    response_model=OrganizationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an organization and its initial owner membership",
)
def create_organization(
    details: OrganizationCreate,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> OrganizationResponse:
    try:
        with unit_of_work() as session:
            organization = OrganizationService(OrganizationRepository(session)).create_organization(
                principal,
                details,
            )
            response = _organization_response(organization)
    except IntegrityError as error:
        if _is_organization_slug_conflict(error):
            raise OrganizationConflict("An organization with that slug already exists.") from None
        raise
    return response


@router.get(
    "/organizations",
    response_model=list[OrganizationResponse],
    summary="List the authenticated user's active organizations",
)
def list_organizations(
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> list[OrganizationResponse]:
    with unit_of_work() as session:
        organizations = OrganizationService(OrganizationRepository(session)).list_organizations(
            principal,
        )
        return [_organization_response(organization) for organization in organizations]


@router.patch(
    "/organizations/{organization_id}",
    response_model=OrganizationResponse,
    summary="Update organization details",
)
def update_organization(
    organization_id: UUID,
    update: OrganizationUpdate,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> OrganizationResponse:
    try:
        with unit_of_work() as session:
            organization = OrganizationLifecycleService(session).update_organization(
                principal,
                organization_id,
                update,
            )
            response = _organization_response(organization)
    except IntegrityError as error:
        if _is_organization_slug_conflict(error):
            raise OrganizationConflict("An organization with that slug already exists.") from None
        raise
    return response


@router.post(
    "/organizations/{organization_id}/suspend",
    response_model=OrganizationResponse,
    summary="Suspend an organization",
)
def suspend_organization(
    organization_id: UUID,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> OrganizationResponse:
    with unit_of_work() as session:
        organization = OrganizationLifecycleService(session).suspend_organization(
            principal,
            organization_id,
        )
        return _organization_response(organization)


@router.post(
    "/organizations/{organization_id}/reactivate",
    response_model=OrganizationResponse,
    summary="Reactivate a suspended organization",
)
def reactivate_organization(
    organization_id: UUID,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> OrganizationResponse:
    with unit_of_work() as session:
        organization = OrganizationLifecycleService(session).reactivate_organization(
            principal,
            organization_id,
        )
        return _organization_response(organization)


@router.get(
    "/organizations/{organization_id}/members",
    response_model=list[OrganizationMemberResponse],
    summary="List organization memberships",
)
def list_members(
    organization_id: UUID,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> list[OrganizationMemberResponse]:
    with unit_of_work() as session:
        return OrganizationLifecycleService(session).list_members(principal, organization_id)


@router.patch(
    "/organizations/{organization_id}/members/{membership_id}",
    response_model=OrganizationMemberResponse,
    summary="Change a member role or status",
)
def update_membership(
    organization_id: UUID,
    membership_id: UUID,
    update: MembershipUpdate,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> OrganizationMemberResponse:
    with unit_of_work() as session:
        membership = OrganizationLifecycleService(session).update_membership(
            principal,
            organization_id,
            membership_id,
            update,
        )
        return _member_response(session, membership)


@router.post(
    "/organizations/{organization_id}/ownership-transfer",
    response_model=list[OrganizationMemberResponse],
    summary="Transfer organization ownership to an active member",
)
def transfer_ownership(
    organization_id: UUID,
    transfer: OwnershipTransfer,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> list[OrganizationMemberResponse]:
    with unit_of_work() as session:
        former_owner, new_owner = OrganizationLifecycleService(session).transfer_ownership(
            principal,
            organization_id,
            transfer.membership_id,
        )
        return [
            _member_response(session, former_owner),
            _member_response(session, new_owner),
        ]


@router.post(
    "/organizations/{organization_id}/invitations",
    response_model=InvitationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a single-use organization invitation",
)
def create_invitation(
    organization_id: UUID,
    details: InvitationCreate,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    http_response: Response,
) -> InvitationResponse:
    with unit_of_work() as session:
        recipient = OrganizationLifecycleService(session).authorize_invitation(
            principal,
            organization_id,
            details,
        )

    try:
        with unit_of_work() as session:
            invitation, token = OrganizationLifecycleService(session).create_invitation(
                principal,
                organization_id,
                details,
                recipient,
            )
            response = InvitationResponse(
                id=invitation.id,
                intended_email=invitation.intended_email,
                role=invitation.role,
                expires_at=invitation.expires_at,
                token=token,
            )
    except (InvalidPrincipalError, OrganizationPermissionDenied):
        raise InvitationUnavailable("The invitation is unavailable.") from None
    except IntegrityError as error:
        if _is_pending_invitation_conflict(error):
            raise OrganizationConflict("A pending invitation already exists.") from None
        raise
    http_response.headers["Cache-Control"] = "no-store"
    return response


@router.delete(
    "/organizations/{organization_id}/invitations/{invitation_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a pending organization invitation",
)
def revoke_invitation(
    organization_id: UUID,
    invitation_id: UUID,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> Response:
    with unit_of_work() as session:
        OrganizationLifecycleService(session).revoke_invitation(
            principal,
            organization_id,
            invitation_id,
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/organization-invitations/accept",
    response_model=MembershipAcceptanceResponse,
    summary="Accept an invitation for the authenticated verified identity",
)
def accept_invitation(
    details: InvitationAccept,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> MembershipAcceptanceResponse:
    with unit_of_work() as session:
        membership = OrganizationLifecycleService(session).accept_invitation(
            principal,
            details.token,
        )
    if membership is None:
        raise InvitationUnavailable("The invitation is unavailable.")
    return MembershipAcceptanceResponse(
        organization_id=membership.organization_id,
        role=membership.role,
        status=membership.status,
    )
