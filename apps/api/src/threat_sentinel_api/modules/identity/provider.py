from typing import Protocol

from pydantic import SecretStr

from threat_sentinel_api.modules.identity.schemas import VerifiedAccessTokenClaims


class AuthenticationProvider(Protocol):
    async def verify_bearer_token(self, bearer_token: SecretStr) -> VerifiedAccessTokenClaims:
        """Verify a credential and return minimal claims; never return the credential itself."""
        ...
