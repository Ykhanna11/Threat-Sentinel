from collections.abc import Iterator
from functools import partial
from typing import Annotated, cast
from uuid import UUID, uuid4

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from threat_sentinel_api import main as api_main
from threat_sentinel_api.api import dependencies as auth_dependencies
from threat_sentinel_api.api import tenant_dependencies
from threat_sentinel_api.db import session as database_session
from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import (
    AuthenticatedPrincipal,
    VerifiedUserContext,
)
from threat_sentinel_api.modules.identity.service import IdentityService
from threat_sentinel_api.modules.tenants.authorization import OrganizationScanAction
from threat_sentinel_api.modules.tenants.context import ActiveOrganizationContext
from threat_sentinel_api.modules.tenants.enums import (
    MembershipStatus,
    OrganizationRole,
    OrganizationStatus,
)
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.schemas import OrganizationCreate
from threat_sentinel_api.modules.tenants.service import OrganizationService

ISSUER = "https://identity.example"


class TrackingSession(Session):
    closed_by_dependency = False

    def close(self) -> None:
        self.closed_by_dependency = True
        super().close()


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = FastAPI()
    app.exception_handlers.update(api_main.app.exception_handlers)
    app.state.tenant_contexts = []

    def context_response(context: ActiveOrganizationContext) -> dict[str, str]:
        app.state.tenant_contexts.append(context)
        return {
            "user_id": str(context.principal.user_id),
            "organization_id": str(context.organization_id),
            "membership_id": str(context.membership_id),
        }

    @app.get("/organizations/{organization_id}/protected")
    def protected(
        context: Annotated[
            ActiveOrganizationContext,
            Depends(tenant_dependencies.get_active_organization_context),
        ],
    ) -> dict[str, str]:
        return context_response(context)

    def register_scan_action_route(
        action: OrganizationScanAction,
        route_action: str,
        method: str,
    ) -> None:
        action_dependency = tenant_dependencies.require_organization_scan_action(action)

        def protected_scan(
            context: Annotated[
                ActiveOrganizationContext,
                Depends(action_dependency),
            ],
        ) -> dict[str, str]:
            return context_response(context)

        protected_scan.__name__ = f"protected_scan_{route_action}"
        app.add_api_route(
            f"/organizations/{{organization_id}}/scans/{route_action}",
            protected_scan,
            methods=[method],
        )

    for action in OrganizationScanAction:
        method = "POST" if action is OrganizationScanAction.CREATE else "GET"
        register_scan_action_route(action, action.value, method)
    register_scan_action_route(cast(OrganizationScanAction, "create"), "raw-create", "POST")

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _create_user(session: Session, subject: str) -> tuple[User, AuthenticatedPrincipal]:
    user_context = VerifiedUserContext(issuer=ISSUER, subject=subject)
    user = IdentityService(IdentityRepository(session)).resolve_verified_user(user_context)
    session.flush()
    identity = session.scalar(
        select(ExternalIdentity).where(
            ExternalIdentity.issuer == ISSUER,
            ExternalIdentity.subject == subject,
        )
    )
    assert identity is not None
    return user, AuthenticatedPrincipal(
        user_id=user.id,
        external_identity_id=identity.id,
        issuer=identity.issuer,
        subject=identity.subject,
    )


def _create_organization(session: Session, owner_subject: str, slug: str) -> Organization:
    owner_context = VerifiedUserContext(issuer=ISSUER, subject=owner_subject)
    IdentityService(IdentityRepository(session)).resolve_verified_user(owner_context)
    session.flush()
    return OrganizationService(OrganizationRepository(session)).create_organization(
        owner_context,
        OrganizationCreate(name=f"Organization {slug}", slug=slug),
    )


def _override_principal(client: TestClient, principal: AuthenticatedPrincipal) -> None:
    client.app.dependency_overrides[auth_dependencies.get_current_principal] = lambda: principal


def _use_database(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    engine: Engine,
    sessions: list[TrackingSession],
) -> list[Session]:
    def session_factory() -> TrackingSession:
        session = TrackingSession(engine, expire_on_commit=False)
        sessions.append(session)
        return session

    monkeypatch.setattr(
        tenant_dependencies,
        "unit_of_work",
        partial(database_session.unit_of_work, session_factory),
    )
    factory_calls: list[Session] = []

    def service_factory(session: Session) -> OrganizationService:
        factory_calls.append(session)
        return OrganizationService(OrganizationRepository(session))

    def override_service_factory() -> tenant_dependencies.OrganizationServiceFactory:
        return service_factory

    client.app.dependency_overrides[tenant_dependencies.get_organization_service_factory] = (
        override_service_factory
    )
    return factory_calls


def _track_membership_lookups(monkeypatch: pytest.MonkeyPatch) -> list[UUID]:
    organization_ids: list[UUID] = []
    original = OrganizationService.require_active_membership

    def track_lookup(
        service: OrganizationService,
        principal: VerifiedUserContext,
        organization_id: UUID,
    ) -> OrganizationMembership:
        organization_ids.append(organization_id)
        return original(service, principal, organization_id)

    monkeypatch.setattr(OrganizationService, "require_active_membership", track_lookup)
    return organization_ids


def test_active_membership_returns_immutable_narrow_context_without_role(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions: list[TrackingSession] = []
    with Session(engine, expire_on_commit=False) as setup_session:
        member, principal = _create_user(setup_session, "active-member")
        organization = _create_organization(setup_session, "owner", "active-org")
        membership = OrganizationMembership(
            organization=organization,
            user=member,
            role=OrganizationRole.ADMIN,
            status=MembershipStatus.ACTIVE,
        )
        setup_session.add(membership)
        setup_session.commit()
        organization_id = organization.id
        membership_id = membership.id
        memberships_before = setup_session.scalar(
            select(func.count()).select_from(OrganizationMembership)
        )

    _override_principal(client, principal)
    factory_calls = _use_database(client, monkeypatch, engine, sessions)

    response = client.get(f"/organizations/{organization_id}/protected")

    assert response.status_code == 200
    assert response.json() == {
        "user_id": str(principal.user_id),
        "organization_id": str(organization_id),
        "membership_id": str(membership_id),
    }
    assert len(factory_calls) == 1
    assert len(sessions) == 1
    assert sessions[0].closed_by_dependency

    context = client.app.state.tenant_contexts[0]
    assert isinstance(context, ActiveOrganizationContext)
    assert context.organization_id == organization_id
    assert context.membership_id == membership_id
    assert set(context.model_dump()) == {"principal", "organization_id", "membership_id"}
    assert context.model_config["frozen"] is True
    assert not hasattr(context, "role")
    assert not hasattr(context, "permissions")
    with pytest.raises(ValidationError):
        context.organization_id = uuid4()  # type: ignore[misc]
    with pytest.raises(ValidationError):
        context.principal = principal  # type: ignore[misc]
    with Session(engine) as verify_session:
        assert (
            verify_session.scalar(select(func.count()).select_from(OrganizationMembership))
            == memberships_before
        )


@pytest.mark.parametrize(
    ("role", "action", "allowed"),
    [
        (OrganizationRole.OWNER, OrganizationScanAction.CREATE, True),
        (OrganizationRole.OWNER, OrganizationScanAction.READ, True),
        (OrganizationRole.OWNER, OrganizationScanAction.LIST, True),
        (OrganizationRole.ADMIN, OrganizationScanAction.CREATE, True),
        (OrganizationRole.ADMIN, OrganizationScanAction.READ, True),
        (OrganizationRole.ADMIN, OrganizationScanAction.LIST, True),
        (OrganizationRole.MEMBER, OrganizationScanAction.CREATE, True),
        (OrganizationRole.MEMBER, OrganizationScanAction.READ, True),
        (OrganizationRole.MEMBER, OrganizationScanAction.LIST, True),
        (OrganizationRole.VIEWER, OrganizationScanAction.CREATE, False),
        (OrganizationRole.VIEWER, OrganizationScanAction.READ, True),
        (OrganizationRole.VIEWER, OrganizationScanAction.LIST, True),
    ],
)
def test_organization_scan_action_dependency_uses_local_membership_role(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    role: OrganizationRole,
    action: OrganizationScanAction,
    allowed: bool,
) -> None:
    sessions: list[TrackingSession] = []
    with Session(engine, expire_on_commit=False) as setup_session:
        user, principal = _create_user(setup_session, f"scan-{role.value}-{action.value}")
        organization = _create_organization(setup_session, "owner", "scan-action-org")
        membership = OrganizationMembership(
            organization=organization,
            user=user,
            role=role,
            status=MembershipStatus.ACTIVE,
        )
        setup_session.add(membership)
        setup_session.commit()
        organization_id = organization.id
        membership_id = membership.id

    _override_principal(client, principal)
    factory_calls = _use_database(client, monkeypatch, engine, sessions)
    membership_lookups = _track_membership_lookups(monkeypatch)

    url = f"/organizations/{organization_id}/scans/{action.value}"
    response = client.post(url) if action is OrganizationScanAction.CREATE else client.get(url)

    assert len(factory_calls) == 1
    assert membership_lookups == [organization_id]
    assert len(sessions) == 1
    assert sessions[0].closed_by_dependency
    if allowed:
        assert response.status_code == 200
        context = client.app.state.tenant_contexts[0]
        assert isinstance(context, ActiveOrganizationContext)
        assert context.principal == principal
        assert context.organization_id == organization_id
        assert context.membership_id == membership_id
        assert context.model_config["frozen"] is True
        assert set(context.model_dump()) == {"principal", "organization_id", "membership_id"}
        assert not hasattr(context, "role")
        assert not hasattr(context, "permissions")
    else:
        assert response.status_code == 403
        assert response.json() == {
            "error": {
                "code": "http_error",
                "message": "The request could not be completed.",
            }
        }
        assert client.app.state.tenant_contexts == []


def test_raw_action_string_fails_closed(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions: list[TrackingSession] = []
    with Session(engine, expire_on_commit=False) as setup_session:
        user, principal = _create_user(setup_session, "raw-action-string")
        organization = _create_organization(setup_session, "owner", "raw-action-org")
        setup_session.add(
            OrganizationMembership(
                organization=organization,
                user=user,
                role=OrganizationRole.OWNER,
                status=MembershipStatus.ACTIVE,
            )
        )
        setup_session.commit()
        organization_id = organization.id

    _override_principal(client, principal)
    factory_calls = _use_database(client, monkeypatch, engine, sessions)
    membership_lookups = _track_membership_lookups(monkeypatch)

    response = client.post(f"/organizations/{organization_id}/scans/raw-create")

    assert response.status_code == 403
    assert response.json() == {
        "error": {
            "code": "http_error",
            "message": "The request could not be completed.",
        }
    }
    assert len(factory_calls) == 1
    assert membership_lookups == [organization_id]
    assert len(sessions) == 1
    assert sessions[0].closed_by_dependency
    assert client.app.state.tenant_contexts == []


def test_membership_role_changes_apply_on_the_next_request(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions: list[TrackingSession] = []
    with Session(engine, expire_on_commit=False) as setup_session:
        user, principal = _create_user(setup_session, "role-changes")
        organization = _create_organization(setup_session, "owner", "role-change-org")
        membership = OrganizationMembership(
            organization=organization,
            user=user,
            role=OrganizationRole.VIEWER,
            status=MembershipStatus.ACTIVE,
        )
        setup_session.add(membership)
        setup_session.commit()
        organization_id = organization.id
        membership_id = membership.id

    _override_principal(client, principal)
    factory_calls = _use_database(client, monkeypatch, engine, sessions)
    membership_lookups = _track_membership_lookups(monkeypatch)

    denied = client.post(f"/organizations/{organization_id}/scans/create")
    assert denied.status_code == 403
    assert client.app.state.tenant_contexts == []

    with Session(engine) as update_session:
        membership = update_session.get(OrganizationMembership, membership_id)
        assert membership is not None
        membership.role = OrganizationRole.MEMBER
        update_session.commit()

    allowed = client.post(f"/organizations/{organization_id}/scans/create")

    assert allowed.status_code == 200
    assert len(factory_calls) == 2
    assert membership_lookups == [organization_id, organization_id]
    assert len(sessions) == 2
    assert all(session.closed_by_dependency for session in sessions)
    assert len(client.app.state.tenant_contexts) == 1


@pytest.mark.parametrize(
    "membership_status",
    [None, MembershipStatus.SUSPENDED, MembershipStatus.REMOVED],
)
def test_missing_suspended_or_removed_membership_is_denied_without_provisioning(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    membership_status: MembershipStatus | None,
) -> None:
    sessions: list[TrackingSession] = []
    with Session(engine, expire_on_commit=False) as setup_session:
        user, principal = _create_user(setup_session, "non-member")
        organization = _create_organization(setup_session, "owner", "private-org")
        if membership_status is not None:
            setup_session.add(
                OrganizationMembership(
                    organization=organization,
                    user=user,
                    role=OrganizationRole.MEMBER,
                    status=membership_status,
                )
            )
        setup_session.commit()
        organization_id = organization.id
        users_before = setup_session.scalar(select(func.count()).select_from(User))
        memberships_before = setup_session.scalar(
            select(func.count()).select_from(OrganizationMembership)
        )

    _override_principal(client, principal)
    _use_database(client, monkeypatch, engine, sessions)

    response = client.get(f"/organizations/{organization_id}/scans/read")

    assert response.status_code == 403
    assert response.json() == {
        "error": {
            "code": "http_error",
            "message": "The request could not be completed.",
        }
    }
    assert len(sessions) == 1
    assert sessions[0].closed_by_dependency
    with Session(engine) as verify_session:
        assert verify_session.scalar(select(func.count()).select_from(User)) == users_before
        assert (
            verify_session.scalar(select(func.count()).select_from(OrganizationMembership))
            == memberships_before
        )


def test_membership_in_another_organization_does_not_authorize_target(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions: list[TrackingSession] = []
    with Session(engine, expire_on_commit=False) as setup_session:
        member, principal = _create_user(setup_session, "one-tenant-member")
        organization_a = _create_organization(setup_session, "owner-a", "tenant-a")
        organization_b = _create_organization(setup_session, "owner-b", "tenant-b")
        setup_session.add(
            OrganizationMembership(
                organization=organization_a,
                user=member,
                role=OrganizationRole.VIEWER,
                status=MembershipStatus.ACTIVE,
            )
        )
        setup_session.commit()
        target_organization_id = organization_b.id

    _override_principal(client, principal)
    _use_database(client, monkeypatch, engine, sessions)

    response = client.get(f"/organizations/{target_organization_id}/scans/read")

    assert response.status_code == 403
    assert response.json()["error"]["message"] == "The request could not be completed."
    assert sessions[0].closed_by_dependency


def test_missing_organization_is_indistinguishable_from_other_access_denials(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions: list[TrackingSession] = []
    with Session(engine, expire_on_commit=False) as setup_session:
        _member, principal = _create_user(setup_session, "missing-org-member")
        _create_organization(setup_session, "owner", "existing-org")
        setup_session.commit()

    _override_principal(client, principal)
    _use_database(client, monkeypatch, engine, sessions)

    response = client.get(f"/organizations/{uuid4()}/scans/read")

    assert response.status_code == 403
    assert response.json()["error"]["message"] == "The request could not be completed."
    assert sessions[0].closed_by_dependency


@pytest.mark.parametrize(
    "organization_status",
    [OrganizationStatus.SUSPENDED, OrganizationStatus.ARCHIVED],
)
def test_inactive_organization_is_denied_generically(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    organization_status: OrganizationStatus,
) -> None:
    sessions: list[TrackingSession] = []
    with Session(engine, expire_on_commit=False) as setup_session:
        member, principal = _create_user(setup_session, "inactive-organization-member")
        organization = _create_organization(setup_session, "owner", "suspended-org")
        organization.status = organization_status
        setup_session.add(
            OrganizationMembership(
                organization=organization,
                user=member,
                role=OrganizationRole.MEMBER,
                status=MembershipStatus.ACTIVE,
            )
        )
        setup_session.commit()
        organization_id = organization.id

    _override_principal(client, principal)
    _use_database(client, monkeypatch, engine, sessions)

    response = client.get(f"/organizations/{organization_id}/scans/read")

    assert response.status_code == 403
    assert "suspended" not in response.text
    assert len(sessions) == 1
    assert sessions[0].closed_by_dependency


def test_inactive_local_user_is_denied_even_with_active_membership(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sessions: list[TrackingSession] = []
    with Session(engine, expire_on_commit=False) as setup_session:
        member, principal = _create_user(setup_session, "inactive-local-user")
        organization = _create_organization(setup_session, "owner", "active-org-for-suspended-user")
        setup_session.add(
            OrganizationMembership(
                organization=organization,
                user=member,
                role=OrganizationRole.MEMBER,
                status=MembershipStatus.ACTIVE,
            )
        )
        setup_session.commit()
        organization_id = organization.id
        member.status = UserStatus.SUSPENDED
        setup_session.commit()

    _override_principal(client, principal)
    _use_database(client, monkeypatch, engine, sessions)

    response = client.get(f"/organizations/{organization_id}/scans/read")

    assert response.status_code == 403
    assert "suspended" not in response.text
    assert len(sessions) == 1
    assert sessions[0].closed_by_dependency


def test_unauthenticated_request_keeps_generic_bearer_challenge(client: TestClient) -> None:
    response = client.post(f"/organizations/{uuid4()}/scans/create")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {
        "error": {
            "code": "http_error",
            "message": "The request could not be completed.",
        }
    }


def test_malformed_organization_uuid_uses_generic_validation_envelope(client: TestClient) -> None:
    _override_principal(
        client,
        AuthenticatedPrincipal(
            user_id=uuid4(),
            external_identity_id=uuid4(),
            issuer=ISSUER,
            subject="malformed-path-test",
        ),
    )

    response = client.get("/organizations/not-a-uuid/protected")

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "request_validation_error"
    assert error["message"] == "Request validation failed."
    assert error["details"][0]["location"] == ["path", "organization_id"]
    assert error["details"][0]["message"].startswith("Input should be a valid UUID")
    assert error["details"][0]["type"] == "uuid_parsing"
    assert "not-a-uuid" not in response.text


def test_unexpected_database_error_is_generic_and_closes_session(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    sessions: list[TrackingSession] = []
    with Session(engine, expire_on_commit=False) as setup_session:
        _member, principal = _create_user(setup_session, "database-error-member")
        organization = _create_organization(setup_session, "owner", "db-error-org")
        setup_session.commit()
        organization_id = organization.id

    _override_principal(client, principal)

    class BrokenOrganizationService:
        def require_active_membership(
            self,
            _principal: AuthenticatedPrincipal,
            _organization_id: UUID,
        ) -> OrganizationMembership:
            raise OperationalError(
                "SELECT membership",
                {},
                RuntimeError("private database connection detail"),
            )

    def broken_factory(_session: Session) -> OrganizationService:
        return cast(OrganizationService, BrokenOrganizationService())

    def override_broken_factory() -> tenant_dependencies.OrganizationServiceFactory:
        return broken_factory

    monkeypatch.setattr(
        tenant_dependencies,
        "unit_of_work",
        partial(
            database_session.unit_of_work,
            lambda: _tracking_session(engine, sessions),
        ),
    )
    client.app.dependency_overrides[tenant_dependencies.get_organization_service_factory] = (
        override_broken_factory
    )

    response = client.get(f"/organizations/{organization_id}/protected")

    assert response.status_code == 500
    assert "private database connection detail" not in response.text
    assert "private database connection detail" not in caplog.text
    assert len(sessions) == 1
    assert sessions[0].closed_by_dependency


def _tracking_session(engine: Engine, sessions: list[TrackingSession]) -> TrackingSession:
    session = TrackingSession(engine, expire_on_commit=False)
    sessions.append(session)
    return session
