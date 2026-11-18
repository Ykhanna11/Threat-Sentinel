from collections.abc import Iterable
from uuid import UUID

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


def require_active_owner_after_changes(
    memberships: Iterable[OrganizationMembership],
    changes: dict[UUID, tuple[OrganizationRole, MembershipStatus]],
) -> None:
    has_active_owner = any(
        changes.get(membership.id, (membership.role, membership.status))[0]
        is OrganizationRole.OWNER
        and changes.get(membership.id, (membership.role, membership.status))[1]
        is MembershipStatus.ACTIVE
        for membership in memberships
    )
    if not has_active_owner:
        raise ActiveOwnerRetentionError("An organization must retain at least one active owner.")
