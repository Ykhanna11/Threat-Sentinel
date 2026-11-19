from collections.abc import Generator
from contextlib import contextmanager
from uuid import UUID

from threat_sentinel_api.modules.audit.recording import (
    UnitOfWorkFactory,
    record_failure_event,
)
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.identity.service import (
    InactiveUserError,
    InvalidPrincipalError,
)
from threat_sentinel_api.modules.tenants.lifecycle_service import (
    InvitationUnavailable,
    MembershipNotFound,
)
from threat_sentinel_api.modules.tenants.service import (
    OrganizationAccessDenied,
    OrganizationPermissionDenied,
)


def _failure_reason(error: Exception) -> str:
    if isinstance(error, OrganizationPermissionDenied):
        return "insufficient_role"
    if isinstance(error, InactiveUserError):
        return "inactive_account"
    if isinstance(error, InvalidPrincipalError):
        return "invalid_principal"
    if isinstance(error, MembershipNotFound):
        return "resource_unavailable"
    if isinstance(error, InvitationUnavailable):
        return "invitation_unavailable"
    return "scope_unavailable"


@contextmanager
def audit_authorization_denials(
    principal: AuthenticatedPrincipal,
    action: str,
    *,
    organization_id: UUID | None = None,
    target_type: str | None = None,
    target_id: UUID | None = None,
    unit_of_work_factory: UnitOfWorkFactory,
) -> Generator[None, None, None]:
    try:
        yield
    except (
        InvalidPrincipalError,
        OrganizationAccessDenied,
        MembershipNotFound,
        InvitationUnavailable,
    ) as error:
        record_failure_event(
            principal,
            action,
            _failure_reason(error),
            organization_id=organization_id,
            target_type=target_type,
            target_id=target_id,
            unit_of_work_factory=unit_of_work_factory,
        )
        raise
