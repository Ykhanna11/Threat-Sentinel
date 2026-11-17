from typing import Protocol

from pydantic import SecretStr

from threat_sentinel_api.modules.identity.schemas import VerifiedUserContext


class AuthenticationProvider(Protocol):
    async def verify_bearer_token(self, bearer_token: SecretStr) -> VerifiedUserContext:
        """Validate a credential and return normalized, verified identity claims."""
        ...
