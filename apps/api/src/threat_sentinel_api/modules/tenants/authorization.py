from enum import StrEnum

from threat_sentinel_api.modules.tenants.enums import OrganizationRole


class OrganizationScanAction(StrEnum):
    """Locally defined actions supported by the organization scan policy."""

    CREATE = "create"
    READ = "read"
    LIST = "list"


class OrganizationTargetAction(StrEnum):
    """Organization target-management actions, separate from the Phase 2 scan policy."""

    CREATE = "create"
    ROTATE_CHALLENGE = "rotate_challenge"
    REVOKE_CHALLENGE = "revoke_challenge"
    VERIFY = "verify"


_ALLOWED_ROLES_BY_ACTION: dict[OrganizationScanAction, frozenset[OrganizationRole]] = {
    OrganizationScanAction.CREATE: frozenset(
        {
            OrganizationRole.OWNER,
            OrganizationRole.ADMIN,
            OrganizationRole.MEMBER,
        }
    ),
    OrganizationScanAction.READ: frozenset(
        {
            OrganizationRole.OWNER,
            OrganizationRole.ADMIN,
            OrganizationRole.MEMBER,
            OrganizationRole.VIEWER,
        }
    ),
    OrganizationScanAction.LIST: frozenset(
        {
            OrganizationRole.OWNER,
            OrganizationRole.ADMIN,
            OrganizationRole.MEMBER,
            OrganizationRole.VIEWER,
        }
    ),
}


_ALLOWED_TARGET_ROLES = frozenset({OrganizationRole.OWNER, OrganizationRole.ADMIN})


def allows_organization_scan_action(
    role: OrganizationRole,
    action: OrganizationScanAction,
) -> bool:
    """Return whether a locally assigned role allows a locally selected scan action."""
    if not isinstance(role, OrganizationRole) or not isinstance(action, OrganizationScanAction):
        return False

    allowed_roles = _ALLOWED_ROLES_BY_ACTION.get(action)
    return allowed_roles is not None and role in allowed_roles


def allows_organization_target_action(
    role: OrganizationRole,
    action: OrganizationTargetAction,
) -> bool:
    """Return whether a locally assigned role may manage organization targets."""
    if not isinstance(role, OrganizationRole) or not isinstance(action, OrganizationTargetAction):
        return False
    return role in _ALLOWED_TARGET_ROLES
