from uuid import UUID

from pydantic import BaseModel, ConfigDict

from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal


class ActiveOrganizationContext(BaseModel):
    """Internal, immutable result of checking local organization membership."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    principal: AuthenticatedPrincipal
    organization_id: UUID
    membership_id: UUID
