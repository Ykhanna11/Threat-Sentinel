from contextlib import asynccontextmanager
from typing import AsyncIterator
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from threat_sentinel_api.api.v1.router import api_router
from threat_sentinel_api.core.config import get_settings
from threat_sentinel_api.core.logging import configure_logging, get_logger
from threat_sentinel_api.modules.identity.lifecycle_service import AccountLifecycleConflict
from threat_sentinel_api.modules.identity.service import InvalidPrincipalError
from threat_sentinel_api.modules.scans.service import ScanNotFound
from threat_sentinel_api.modules.tenants.service import (
    OrganizationConflict,
    OrganizationPermissionDenied,
    OrganizationScopeUnavailable,
)
from threat_sentinel_api.modules.tenants.invariants import ActiveOwnerRetentionError
from threat_sentinel_api.modules.tenants.lifecycle_service import (
    InvitationUnavailable,
    MembershipNotFound,
)

logger = get_logger(__name__)
settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    configure_logging(settings.log_level)
    yield


app = FastAPI(
    title="ThreatSentinel API",
    description=(
        "ThreatSentinel API foundation with authenticated scan-record persistence. "
        "Scan execution and analysis are not implemented."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )


@app.middleware("http")
async def log_request(request: Request, call_next):
    request_id = str(uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "http_request_completed",
        extra={
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
        },
    )
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
    details = [
        {"location": list(error["loc"]), "message": error["msg"], "type": error["type"]}
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "request_validation_error",
                "message": "Request validation failed.",
                "details": details,
            }
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        headers=exc.headers,
        content={
            "error": {
                "code": "http_error",
                "message": "The request could not be completed.",
            }
        },
    )


def _authorization_error_response(
    status_code: int,
    *,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        headers=headers,
        content={
            "error": {
                "code": "http_error",
                "message": "The request could not be completed.",
            }
        },
    )


@app.exception_handler(ScanNotFound)
async def scan_not_found_handler(_: Request, _exc: ScanNotFound) -> JSONResponse:
    return _authorization_error_response(404)


@app.exception_handler(OrganizationScopeUnavailable)
async def organization_scope_unavailable_handler(
    _: Request,
    _exc: OrganizationScopeUnavailable,
) -> JSONResponse:
    return _authorization_error_response(404)


@app.exception_handler(OrganizationPermissionDenied)
async def organization_permission_denied_handler(
    _: Request,
    _exc: OrganizationPermissionDenied,
) -> JSONResponse:
    return _authorization_error_response(403)


@app.exception_handler(OrganizationConflict)
@app.exception_handler(AccountLifecycleConflict)
async def organization_conflict_handler(
    _: Request,
    _exc: OrganizationConflict | AccountLifecycleConflict,
) -> JSONResponse:
    return _authorization_error_response(409)


@app.exception_handler(ActiveOwnerRetentionError)
async def active_owner_retention_handler(
    _: Request,
    _exc: ActiveOwnerRetentionError,
) -> JSONResponse:
    return _authorization_error_response(409)


@app.exception_handler(MembershipNotFound)
@app.exception_handler(InvitationUnavailable)
async def lifecycle_resource_unavailable_handler(
    _: Request,
    _exc: Exception,
) -> JSONResponse:
    return _authorization_error_response(404)


@app.exception_handler(InvalidPrincipalError)
async def invalid_principal_handler(
    _: Request,
    _exc: InvalidPrincipalError,
) -> JSONResponse:
    return _authorization_error_response(
        401,
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "unhandled_application_error",
        extra={
            "request_id": getattr(request.state, "request_id", None),
            "error_type": type(exc).__name__,
        },
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "internal_server_error",
                "message": "An unexpected error occurred.",
            }
        },
    )


app.include_router(api_router, prefix="/api/v1")
