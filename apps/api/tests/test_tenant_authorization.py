from typing import cast

import pytest

from threat_sentinel_api.modules.tenants.authorization import (
    OrganizationScanAction,
    allows_organization_scan_action,
)
from threat_sentinel_api.modules.tenants.enums import OrganizationRole


@pytest.mark.parametrize(
    ("role", "action", "expected"),
    [
        pytest.param(
            OrganizationRole.OWNER, OrganizationScanAction.CREATE, True, id="owner-create"
        ),
        pytest.param(OrganizationRole.OWNER, OrganizationScanAction.READ, True, id="owner-read"),
        pytest.param(OrganizationRole.OWNER, OrganizationScanAction.LIST, True, id="owner-list"),
        pytest.param(
            OrganizationRole.ADMIN, OrganizationScanAction.CREATE, True, id="admin-create"
        ),
        pytest.param(OrganizationRole.ADMIN, OrganizationScanAction.READ, True, id="admin-read"),
        pytest.param(OrganizationRole.ADMIN, OrganizationScanAction.LIST, True, id="admin-list"),
        pytest.param(
            OrganizationRole.MEMBER,
            OrganizationScanAction.CREATE,
            True,
            id="member-create",
        ),
        pytest.param(OrganizationRole.MEMBER, OrganizationScanAction.READ, True, id="member-read"),
        pytest.param(OrganizationRole.MEMBER, OrganizationScanAction.LIST, True, id="member-list"),
        pytest.param(
            OrganizationRole.VIEWER, OrganizationScanAction.CREATE, False, id="viewer-create"
        ),
        pytest.param(OrganizationRole.VIEWER, OrganizationScanAction.READ, True, id="viewer-read"),
        pytest.param(OrganizationRole.VIEWER, OrganizationScanAction.LIST, True, id="viewer-list"),
    ],
)
def test_organization_scan_action_policy(
    role: OrganizationRole,
    action: OrganizationScanAction,
    expected: bool,
) -> None:
    assert allows_organization_scan_action(role, action) is expected


@pytest.mark.parametrize(
    ("role", "action"),
    [
        pytest.param("owner", OrganizationScanAction.CREATE, id="raw-role-string"),
        pytest.param(OrganizationRole.OWNER, "create", id="raw-action-string"),
        pytest.param(OrganizationRole.OWNER, "delete", id="unknown-action"),
        pytest.param(None, OrganizationScanAction.CREATE, id="none-role"),
        pytest.param(OrganizationRole.OWNER, None, id="none-action"),
        pytest.param(object(), OrganizationScanAction.CREATE, id="unrelated-role-object"),
        pytest.param(OrganizationRole.OWNER, object(), id="unrelated-action-object"),
    ],
)
def test_invalid_role_or_action_fails_closed(role: object, action: object) -> None:
    assert not allows_organization_scan_action(
        cast(OrganizationRole, role),
        cast(OrganizationScanAction, action),
    )
