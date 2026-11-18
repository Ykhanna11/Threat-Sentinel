import asyncio
import math
from datetime import UTC, datetime
from typing import Any

import jwt
from pydantic import SecretStr, ValidationError

from threat_sentinel_api.core.config import Settings
from threat_sentinel_api.modules.identity.auth_errors import (
    AuthenticationVerificationError,
    AuthenticationVerifierFailure,
    InvalidAccessToken,
)
from threat_sentinel_api.modules.identity.jwks import TrustedJwksKeyStore
from threat_sentinel_api.modules.identity.schemas import VerifiedAccessTokenClaims

MAX_BEARER_TOKEN_LENGTH = 16 * 1024
_REQUIRED_CLAIMS = ("exp", "iat", "sub", "iss", "aud")
_FORBIDDEN_KEY_HEADERS = frozenset({"jku", "jwk", "x5u", "x5c", "crit", "b64"})


def _numeric_date(claims: dict[str, Any], name: str, *, required: bool) -> datetime | None:
    value = claims.get(name)
    if value is None and not required:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise InvalidAccessToken("Invalid access token.")
    try:
        return datetime.fromtimestamp(value, UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise InvalidAccessToken("Invalid access token.") from exc


class JwtAccessTokenVerifier:
    """Verify compact JWT access tokens using one configured trusted JWKS source."""

    def __init__(
        self,
        settings: Settings,
        *,
        key_store: TrustedJwksKeyStore | None = None,
    ) -> None:
        if (
            settings.auth_expected_issuer is None
            or settings.auth_expected_audience is None
            or settings.auth_trusted_jwks_url is None
            or settings.auth_allowed_jwt_algorithms is None
        ):
            raise ValueError("Complete authentication configuration is required.")
        self._issuer = settings.auth_expected_issuer
        self._audience = settings.auth_expected_audience
        self._algorithms = tuple(settings.auth_allowed_jwt_algorithms)
        self._leeway = settings.auth_clock_skew_seconds
        self._key_store = key_store if key_store is not None else TrustedJwksKeyStore(settings)

    async def verify_bearer_token(self, bearer_token: SecretStr) -> VerifiedAccessTokenClaims:
        try:
            token = bearer_token.get_secret_value()
            return await asyncio.to_thread(self._verify, token)
        except AuthenticationVerificationError:
            raise
        except Exception as exc:
            raise AuthenticationVerifierFailure("Authentication verifier failed.") from exc

    def _verify(self, token: str) -> VerifiedAccessTokenClaims:
        if (
            not token
            or len(token) > MAX_BEARER_TOKEN_LENGTH
            or token != token.strip()
            or any(character.isspace() for character in token)
        ):
            raise InvalidAccessToken("Invalid access token.")

        try:
            header = jwt.get_unverified_header(token)
        except (jwt.PyJWTError, TypeError, ValueError) as exc:
            raise InvalidAccessToken("Invalid access token.") from exc

        if (
            not isinstance(header, dict)
            or _FORBIDDEN_KEY_HEADERS.intersection(header)
            or header.get("typ") != "at+jwt"
        ):
            raise InvalidAccessToken("Invalid access token.")

        algorithm = header.get("alg")
        kid = header.get("kid")
        if (
            not isinstance(algorithm, str)
            or algorithm not in self._algorithms
            or not isinstance(kid, str)
            or not kid.strip()
            or len(kid) > 256
        ):
            raise InvalidAccessToken("Invalid access token.")

        key = self._key_store.get_key(kid, algorithm)
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=[algorithm],
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={
                    "require": list(_REQUIRED_CLAIMS),
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "strict_aud": False,
                },
            )
        except (jwt.PyJWTError, TypeError, ValueError) as exc:
            raise InvalidAccessToken("Invalid access token.") from exc

        subject = claims.get("sub")
        audiences = claims.get("aud")
        if (
            claims.get("iss") != self._issuer
            or not isinstance(subject, str)
            or not subject.strip()
            or len(subject) > 512
        ):
            raise InvalidAccessToken("Invalid access token.")
        if isinstance(audiences, str):
            audiences = (audiences,)
        elif isinstance(audiences, list):
            audiences = tuple(audiences)
        else:
            raise InvalidAccessToken("Invalid access token.")
        if (
            not audiences
            or any(not isinstance(audience, str) or not audience.strip() for audience in audiences)
            or self._audience not in audiences
        ):
            raise InvalidAccessToken("Invalid access token.")

        issued_at = _numeric_date(claims, "iat", required=True)
        expires_at = _numeric_date(claims, "exp", required=True)
        not_before = _numeric_date(claims, "nbf", required=False)
        if (
            issued_at is None
            or expires_at is None
            or expires_at <= issued_at
            or (not_before is not None and not_before >= expires_at)
        ):
            raise InvalidAccessToken("Invalid access token.")

        email = claims.get("email")
        email_verified = claims.get("email_verified")
        if email is not None and not isinstance(email, str):
            raise InvalidAccessToken("Invalid access token.")
        if email_verified is not None and not isinstance(email_verified, bool):
            raise InvalidAccessToken("Invalid access token.")

        try:
            return VerifiedAccessTokenClaims(
                issuer=claims["iss"],
                subject=subject,
                audiences=audiences,
                issued_at=issued_at,
                expires_at=expires_at,
                not_before=not_before,
                key_id=kid,
                email=email,
                email_verified=email_verified,
                token_type=header["typ"],
            )
        except ValidationError as exc:
            raise InvalidAccessToken("Invalid access token.") from exc
