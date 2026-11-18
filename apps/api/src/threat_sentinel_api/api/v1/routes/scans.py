from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from threat_sentinel_api.api.dependencies import get_current_principal
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.scans.schemas import ScanCreateRequest, ScanResponse
from threat_sentinel_api.modules.scans.service import ScanService

router = APIRouter()


def get_scan_service() -> ScanService:
    """Create the application service; each operation owns its authorization UOW."""
    return ScanService()


@router.post(
    "/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a personal security scan record",
)
def create_personal_scan(
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    service: Annotated[ScanService, Depends(get_scan_service)],
    _request: ScanCreateRequest | None = None,
) -> ScanResponse:
    return ScanResponse.model_validate(service.create_personal_scan(principal))


@router.get(
    "/scans",
    response_model=list[ScanResponse],
    summary="List personal security scan records",
)
def list_personal_scans(
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> list[ScanResponse]:
    return [ScanResponse.model_validate(scan) for scan in service.list_personal_scans(principal)]


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    summary="Retrieve a personal security scan record",
)
def get_personal_scan(
    scan_id: UUID,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> ScanResponse:
    return ScanResponse.model_validate(service.get_personal_scan(principal, scan_id))


@router.post(
    "/organizations/{organization_id}/scans",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an organization security scan record",
)
def create_organization_scan(
    organization_id: UUID,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    service: Annotated[ScanService, Depends(get_scan_service)],
    _request: ScanCreateRequest | None = None,
) -> ScanResponse:
    return ScanResponse.model_validate(service.create_organization_scan(principal, organization_id))


@router.get(
    "/organizations/{organization_id}/scans",
    response_model=list[ScanResponse],
    summary="List organization security scan records",
)
def list_organization_scans(
    organization_id: UUID,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> list[ScanResponse]:
    scans = service.list_organization_scans(principal, organization_id)
    return [ScanResponse.model_validate(scan) for scan in scans]


@router.get(
    "/organizations/{organization_id}/scans/{scan_id}",
    response_model=ScanResponse,
    summary="Retrieve an organization security scan record",
)
def get_organization_scan(
    organization_id: UUID,
    scan_id: UUID,
    principal: Annotated[AuthenticatedPrincipal, Depends(get_current_principal)],
    service: Annotated[ScanService, Depends(get_scan_service)],
) -> ScanResponse:
    return ScanResponse.model_validate(
        service.get_organization_scan(principal, organization_id, scan_id)
    )
