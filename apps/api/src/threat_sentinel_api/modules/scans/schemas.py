from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class ScanCreateRequest(BaseModel):
    """Scan persistence currently has no client-selectable fields."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ScanResponse(BaseModel):
    """Public scan persistence fields; authorization and relationship IDs remain private."""

    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: UUID
    created_at: datetime
