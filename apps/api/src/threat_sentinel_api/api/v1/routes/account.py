from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from threat_sentinel_api.api.dependencies import get_current_principal
from threat_sentinel_api.db.session import unit_of_work
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import (
    AccountProfileResponse,
    AccountProfileUpdate,
    AuthenticatedPrincipal,
)
from threat_sentinel_api.modules.identity.profile_service import AccountProfileService

router = APIRouter(prefix="/account", tags=["account"])


def _service(session: Session) -> AccountProfileService:
    return AccountProfileService(IdentityRepository(session))


@router.get(
    "/profile",
    response_model=AccountProfileResponse,
    summary="Retrieve the authenticated account profile",
)
def get_profile(
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> AccountProfileResponse:
    with unit_of_work() as session:
        return _service(session).get_profile(principal)


@router.patch(
    "/profile",
    response_model=AccountProfileResponse,
    summary="Update the authenticated account profile",
)
def update_profile(
    update: AccountProfileUpdate,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
) -> AccountProfileResponse:
    with unit_of_work() as session:
        return _service(session).update_profile(principal, update)
