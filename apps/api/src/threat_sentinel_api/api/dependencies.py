import asyncio
from collections.abc import Callable
from functools import lru_cache
from typing import Annotated, Protocol

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import SecretStr
from sqlalchemy.orm import Session

from threat_sentinel_api.core.config import get_settings
from threat_sentinel_api.db.session import unit_of_work
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
from threat_sentinel_api.modules.identity.service import IdentityService, InactiveUserError

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


async def get_current_principal(
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
    except InactiveUserError:
        raise _unauthorized() from None
