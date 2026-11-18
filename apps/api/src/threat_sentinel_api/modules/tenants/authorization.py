from enum import StrEnum

from threat_sentinel_api.modules.tenants.enums import OrganizationRole


class OrganizationScanAction(StrEnum):
    """Locally defined actions supported by the organization scan policy."""

    CREATE = "create"
    READ = "read"
    LIST = "list"


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


def allows_organization_scan_action(
    role: OrganizationRole,
    action: OrganizationScanAction,
) -> bool:
    """Return whether a locally assigned role allows a locally selected scan action."""
    if not isinstance(role, OrganizationRole) or not isinstance(action, OrganizationScanAction):
        return False

    allowed_roles = _ALLOWED_ROLES_BY_ACTION.get(action)
    return allowed_roles is not None and role in allowed_roles
