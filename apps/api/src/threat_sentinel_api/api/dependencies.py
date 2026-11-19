import asyncio
from collections.abc import Callable
from functools import lru_cache
from typing import Annotated, Protocol

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr
from sqlalchemy.orm import Session

from threat_sentinel_api.core.config import get_settings
from threat_sentinel_api.db.session import unit_of_work
from threat_sentinel_api.modules.audit.recording import record_failure_event
from threat_sentinel_api.modules.identity.auth_errors import (
    InvalidAccessToken,
    TrustedKeySourceUnavailable,
)
from threat_sentinel_api.modules.identity.jwt_verifier import JwtAccessTokenVerifier
from threat_sentinel_api.modules.identity.provider import AuthenticationProvider
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import (
    AuthenticatedPrincipal,
    VerifiedAccessTokenClaims,
)
from threat_sentinel_api.modules.identity.service import (
    IdentityService,
    InactiveUserError,
    InvalidPrincipalError,
)

_bearer_scheme = HTTPBearer(auto_error=False)


class AuthenticationConfigurationUnavailable(HTTPException):
    """Local trusted authentication configuration is unavailable."""

    def __init__(self) -> None:
        super().__init__(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)


class AuthenticatedIdentityResolver(Protocol):
    def resolve_authenticated_principal(
        self,
        claims: VerifiedAccessTokenClaims,
    ) -> AuthenticatedPrincipal: ...


IdentityServiceFactory = Callable[[Session], AuthenticatedIdentityResolver]


@lru_cache
def get_authentication_provider() -> AuthenticationProvider:
    """Provide one verifier instance so its bounded JWKS cache is reused."""
    settings = get_settings()
    if not settings.authentication_configured:
        raise AuthenticationConfigurationUnavailable from None
    return JwtAccessTokenVerifier(settings)


def get_identity_service_factory() -> IdentityServiceFactory:
    """Provide an overridable factory for services bound to a unit-of-work session."""
    return lambda session: IdentityService(IdentityRepository(session))


def _resolve_principal(
    claims: VerifiedAccessTokenClaims,
    service_factory: IdentityServiceFactory,
) -> AuthenticatedPrincipal:
    with unit_of_work() as session:
        return service_factory(session).resolve_authenticated_principal(claims)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_bearer_token(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_bearer_scheme),
    ],
) -> SecretStr:
    """Extract a nonempty bearer token before resolving provider configuration."""
    if (
        credentials is None
        or credentials.scheme.casefold() != "bearer"
        or not credentials.credentials
        or any(character.isspace() for character in credentials.credentials)
    ):
        raise _unauthorized()
    return SecretStr(credentials.credentials)


def _record_account_export_authentication_denial(
    claims: VerifiedAccessTokenClaims,
    error: InvalidPrincipalError,
) -> None:
    with unit_of_work() as session:
        identity = IdentityRepository(session).find_by_issuer_subject(
            claims.issuer,
            claims.subject,
        )
        if identity is None:
            return
        principal = AuthenticatedPrincipal(
            user_id=identity.user_id,
            external_identity_id=identity.id,
            issuer=identity.issuer,
            subject=identity.subject,
            email=identity.email,
            email_verified=identity.email_verified_at is not None,
        )

    record_failure_event(
        principal,
        "account.export_denied",
        "inactive_account" if isinstance(error, InactiveUserError) else "invalid_principal",
        target_type="user",
        target_id=principal.user_id,
        unit_of_work_factory=lambda: unit_of_work(),
    )


async def get_current_principal(
    request: Request,
    bearer_token: Annotated[SecretStr, Depends(get_bearer_token)],
    provider: Annotated[AuthenticationProvider, Depends(get_authentication_provider)],
    service_factory: Annotated[
        IdentityServiceFactory,
        Depends(get_identity_service_factory),
    ],
) -> AuthenticatedPrincipal:
    """Authenticate a bearer credential and resolve its active local identity."""
    try:
        claims = await provider.verify_bearer_token(bearer_token)
    except InvalidAccessToken:
        raise _unauthorized() from None
    except TrustedKeySourceUnavailable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        ) from None

    try:
        return await asyncio.to_thread(_resolve_principal, claims, service_factory)
    except InvalidPrincipalError as error:
        if request.method == "GET" and request.url.path == "/api/v1/account/export":
            await asyncio.to_thread(
                _record_account_export_authentication_denial,
                claims,
                error,
            )
        raise _unauthorized() from None
