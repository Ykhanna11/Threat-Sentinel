from collections.abc import Iterable

from threat_sentinel_api.modules.tenants.enums import MembershipStatus, OrganizationRole
from threat_sentinel_api.modules.tenants.models import OrganizationMembership


class ActiveOwnerRetentionError(ValueError):
    """Raised when a proposed membership state leaves an organization without an active owner."""


def require_active_owner(memberships: Iterable[OrganizationMembership]) -> None:
    """Validate projected post-change memberships before a role/removal operation is applied."""
    if not any(
        membership.role is OrganizationRole.OWNER and membership.status is MembershipStatus.ACTIVE
        for membership in memberships
    ):
        raise ActiveOwnerRetentionError("An organization must retain at least one active owner.")
