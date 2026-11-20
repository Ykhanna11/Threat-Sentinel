from threat_sentinel_api.db.base import Base
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.tenants.models import (
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
)
from threat_sentinel_api.modules.scans.models import SecurityScan
from threat_sentinel_api.modules.audit.models import SecurityAuditEvent
from threat_sentinel_api.modules.targets.models import (
    SecurityTarget,
    TargetVerificationChallenge,
)

metadata = Base.metadata

__all__ = [
    "ExternalIdentity",
    "Organization",
    "OrganizationInvitation",
    "OrganizationMembership",
    "SecurityScan",
    "SecurityAuditEvent",
    "SecurityTarget",
    "TargetVerificationChallenge",
    "User",
    "metadata",
]
