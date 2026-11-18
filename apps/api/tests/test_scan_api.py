from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from threat_sentinel_api import main as api_main
from threat_sentinel_api.api import dependencies as auth_dependencies
from threat_sentinel_api.api.v1.routes import scans as scan_routes
from threat_sentinel_api.core.config import Settings
from threat_sentinel_api.db import session as database_session
from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import (
    AuthenticatedPrincipal,
    VerifiedAccessTokenClaims,
)
from threat_sentinel_api.modules.identity.service import IdentityService
from threat_sentinel_api.modules.scans.models import SecurityScan
from threat_sentinel_api.modules.scans.service import ScanService
from threat_sentinel_api.modules.tenants.enums import (
    MembershipStatus,
    OrganizationRole,
    OrganizationStatus,
)
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership

ISSUER = "https://issuer.example"
GENERIC_ERROR = {
    "error": {
        "code": "http_error",
        "message": "The request could not be completed.",
    }
}


def _claims(subject: str = "scan-api-user") -> VerifiedAccessTokenClaims:
    now = datetime.now(UTC)
    return VerifiedAccessTokenClaims(
        issuer=ISSUER,
        subject=subject,
        audiences=("threat-sentinel-api",),
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )


class StubProvider:
    def __init__(self, claims: VerifiedAccessTokenClaims) -> None:
        self.claims = claims
        self.received_tokens: list[str] = []

    async def verify_bearer_token(self, bearer_token: SecretStr) -> VerifiedAccessTokenClaims:
        self.received_tokens.append(bearer_token.get_secret_value())
        return self.claims


class RecordingScanService(ScanService):
    def __init__(self, session_factory: Callable[[], Session], calls: list[str]) -> None:
        super().__init__(session_factory)
        self._calls = calls

    def create_personal_scan(self, principal: AuthenticatedPrincipal) -> SecurityScan:
        self._calls.append("create_personal_scan")
        return super().create_personal_scan(principal)

    def list_personal_scans(self, principal: AuthenticatedPrincipal) -> list[SecurityScan]:
        self._calls.append("list_personal_scans")
        return super().list_personal_scans(principal)

    def get_personal_scan(
        self,
        principal: AuthenticatedPrincipal,
        scan_id: UUID,
    ) -> SecurityScan:
        self._calls.append("get_personal_scan")
        return super().get_personal_scan(principal, scan_id)

    def create_organization_scan(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
    ) -> SecurityScan:
        self._calls.append("create_organization_scan")
        return super().create_organization_scan(principal, organization_id)

    def list_organization_scans(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
    ) -> list[SecurityScan]:
        self._calls.append("list_organization_scans")
        return super().list_organization_scans(principal, organization_id)

    def get_organization_scan(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        scan_id: UUID,
    ) -> SecurityScan:
        self._calls.append("get_organization_scan")
        return super().get_organization_scan(principal, organization_id, scan_id)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(api_main.app, raise_server_exceptions=False) as test_client:
        yield test_client
    api_main.app.dependency_overrides.clear()


def _configure_client(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    claims: VerifiedAccessTokenClaims,
) -> tuple[StubProvider, list[str], sessionmaker[Session]]:
    provider = StubProvider(claims)
    calls: list[str] = []
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    client.app.dependency_overrides[auth_dependencies.get_authentication_provider] = lambda: (
        provider
    )
    client.app.dependency_overrides[scan_routes.get_scan_service] = lambda: RecordingScanService(
        factory, calls
    )
    client.headers["Authorization"] = "Bearer test-token"
    monkeypatch.setattr(
        auth_dependencies,
        "unit_of_work",
        partial(database_session.unit_of_work, factory),
    )
    return provider, calls, factory


def _create_local_user(
    session: Session,
    claims: VerifiedAccessTokenClaims,
) -> AuthenticatedPrincipal:
    principal = IdentityService(IdentityRepository(session)).resolve_authenticated_principal(claims)
    session.flush()
    return principal


def _create_organization(
    session: Session,
    creator_id: UUID,
    slug: str,
    *,
    status: OrganizationStatus = OrganizationStatus.ACTIVE,
) -> Organization:
    organization = Organization(
        name=f"Organization {slug}",
        slug=slug,
        created_by_user_id=creator_id,
        status=status,
    )
    session.add(organization)
    session.flush()
    return organization


def _add_membership(
    session: Session,
    organization_id: UUID,
    user_id: UUID,
    role: OrganizationRole = OrganizationRole.MEMBER,
    status: MembershipStatus = MembershipStatus.ACTIVE,
) -> OrganizationMembership:
    membership = OrganizationMembership(
        organization_id=organization_id,
        user_id=user_id,
        role=role,
        status=status,
    )
    session.add(membership)
    session.flush()
    return membership


def _add_personal_scan(session: Session, owner_id: UUID) -> SecurityScan:
    scan = SecurityScan(owner_user_id=owner_id, created_by_user_id=owner_id)
    session.add(scan)
    session.flush()
    return scan


def _add_organization_scan(
    session: Session,
    organization_id: UUID,
    creator_id: UUID,
) -> SecurityScan:
    scan = SecurityScan(organization_id=organization_id, created_by_user_id=creator_id)
    session.add(scan)
    session.flush()
    return scan


def _assert_same_generic_error(left: Any, right: Any, status_code: int) -> None:
    assert left.status_code == status_code
    assert right.status_code == status_code
    assert left.json() == right.json() == GENERIC_ERROR
    assert left.headers.get("www-authenticate") == right.headers.get("www-authenticate")
    assert left.headers.get("www-authenticate") is None


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("post", "/api/v1/scans"),
        ("get", "/api/v1/scans"),
        ("get", f"/api/v1/scans/{uuid4()}"),
        ("post", f"/api/v1/organizations/{uuid4()}/scans"),
        ("get", f"/api/v1/organizations/{uuid4()}/scans"),
        ("get", f"/api/v1/organizations/{uuid4()}/scans/{uuid4()}"),
    ],
)
def test_all_scan_routes_require_authentication(
    client: TestClient,
    method: str,
    path: str,
) -> None:
    response = getattr(client, method)(path)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == GENERIC_ERROR


def test_personal_routes_use_service_scope_and_hide_creator_and_owner(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = _claims()
    provider, calls, _ = _configure_client(client, engine, monkeypatch, claims)
    other_claims = _claims("other-personal-user")
    with Session(engine, expire_on_commit=False) as setup_session:
        principal = _create_local_user(setup_session, claims)
        other_principal = _create_local_user(setup_session, other_claims)
        other_scan = _add_personal_scan(setup_session, other_principal.user_id)
        owned_scan = _add_personal_scan(setup_session, principal.user_id)
        setup_session.commit()

    created_response = client.post("/api/v1/scans")
    assert created_response.status_code == 201
    created = created_response.json()
    assert set(created) == {"id", "created_at"}
    assert UUID(created["id"])
    assert datetime.fromisoformat(created["created_at"])

    with Session(engine) as verify_session:
        created_scan = verify_session.get(SecurityScan, UUID(created["id"]))
        assert created_scan is not None
        assert created_scan.owner_user_id == principal.user_id
        assert created_scan.created_by_user_id == principal.user_id
        assert created_scan.organization_id is None

    listed_response = client.get("/api/v1/scans")
    assert listed_response.status_code == 200
    assert {item["id"] for item in listed_response.json()} == {
        str(owned_scan.id),
        created["id"],
    }
    assert str(other_scan.id) not in listed_response.text

    own_response = client.get(f"/api/v1/scans/{owned_scan.id}")
    assert own_response.status_code == 200
    assert set(own_response.json()) == {"id", "created_at"}
    cross_user_response = client.get(f"/api/v1/scans/{other_scan.id}")
    missing_response = client.get(f"/api/v1/scans/{uuid4()}")
    _assert_same_generic_error(cross_user_response, missing_response, 404)

    assert provider.received_tokens == ["test-token"] * 5
    assert calls == [
        "create_personal_scan",
        "list_personal_scans",
        "get_personal_scan",
        "get_personal_scan",
        "get_personal_scan",
    ]


@pytest.mark.parametrize(
    "field",
    [
        "owner_user_id",
        "created_by_user_id",
        "organization_id",
        "role",
        "permissions",
        "membership",
        "groups",
    ],
)
def test_create_requests_reject_client_ownership_and_authorization_fields(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    claims = _claims(f"inject-{field}")
    _configure_client(client, engine, monkeypatch, claims)
    with Session(engine, expire_on_commit=False) as setup_session:
        principal = _create_local_user(setup_session, claims)
        organization = _create_organization(
            setup_session,
            principal.user_id,
            f"inject-{field}",
        )
        setup_session.commit()

    for path in (
        "/api/v1/scans",
        f"/api/v1/organizations/{organization.id}/scans",
    ):
        response = client.post(path, json={field: str(uuid4())})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "request_validation_error"
        assert str(principal.user_id) not in response.text

    with Session(engine) as verify_session:
        assert verify_session.scalar(select(func.count()).select_from(SecurityScan)) == 0


@pytest.mark.parametrize(
    ("role", "action", "allowed"),
    [
        (OrganizationRole.OWNER, "create", True),
        (OrganizationRole.OWNER, "read", True),
        (OrganizationRole.OWNER, "list", True),
        (OrganizationRole.ADMIN, "create", True),
        (OrganizationRole.ADMIN, "read", True),
        (OrganizationRole.ADMIN, "list", True),
        (OrganizationRole.MEMBER, "create", True),
        (OrganizationRole.MEMBER, "read", True),
        (OrganizationRole.MEMBER, "list", True),
        (OrganizationRole.VIEWER, "create", False),
        (OrganizationRole.VIEWER, "read", True),
        (OrganizationRole.VIEWER, "list", True),
    ],
)
def test_organization_routes_enforce_local_role_matrix(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    role: OrganizationRole,
    action: str,
    allowed: bool,
) -> None:
    claims = _claims(f"role-{role.value}-{action}")
    _, calls, _ = _configure_client(client, engine, monkeypatch, claims)
    with Session(engine, expire_on_commit=False) as setup_session:
        principal = _create_local_user(setup_session, claims)
        creator = _create_local_user(setup_session, _claims(f"creator-{role.value}-{action}"))
        organization = _create_organization(
            setup_session,
            creator.user_id,
            f"role-{role.value}-{action}",
        )
        _add_membership(setup_session, organization.id, principal.user_id, role)
        scan = _add_organization_scan(setup_session, organization.id, creator.user_id)
        setup_session.commit()

    collection_path = f"/api/v1/organizations/{organization.id}/scans"
    if action == "create":
        response = client.post(collection_path)
        expected_status = 201 if allowed else 403
        expected_operation = "create_organization_scan"
    elif action == "list":
        response = client.get(collection_path)
        expected_status = 200
        expected_operation = "list_organization_scans"
    else:
        response = client.get(f"{collection_path}/{scan.id}")
        expected_status = 200
        expected_operation = "get_organization_scan"

    assert response.status_code == expected_status
    assert calls == [expected_operation]
    if not allowed:
        assert response.json() == GENERIC_ERROR
        assert str(organization.id) not in response.text
        assert str(principal.user_id) not in response.text
        return

    if action == "create":
        result = response.json()
        assert set(result) == {"id", "created_at"}
        with Session(engine) as verify_session:
            created = verify_session.get(SecurityScan, UUID(result["id"]))
            assert created is not None
            assert created.organization_id == organization.id
            assert created.created_by_user_id == principal.user_id
            assert created.owner_user_id is None
    elif action == "list":
        assert [item["id"] for item in response.json()] == [str(scan.id)]
    else:
        assert response.json()["id"] == str(scan.id)


@pytest.mark.parametrize(
    ("organization_exists", "organization_status", "membership_status"),
    [
        (False, None, None),
        (True, OrganizationStatus.SUSPENDED, MembershipStatus.ACTIVE),
        (True, OrganizationStatus.ARCHIVED, MembershipStatus.ACTIVE),
        (True, OrganizationStatus.ACTIVE, None),
        (True, OrganizationStatus.ACTIVE, MembershipStatus.SUSPENDED),
        (True, OrganizationStatus.ACTIVE, MembershipStatus.REMOVED),
    ],
)
def test_unavailable_organization_scopes_share_generic_not_found(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    organization_exists: bool,
    organization_status: OrganizationStatus | None,
    membership_status: MembershipStatus | None,
) -> None:
    claims = _claims(f"unavailable-{organization_exists}-{organization_status}-{membership_status}")
    _configure_client(client, engine, monkeypatch, claims)
    with Session(engine, expire_on_commit=False) as setup_session:
        principal = _create_local_user(setup_session, claims)
        if organization_exists:
            organization = _create_organization(
                setup_session,
                principal.user_id,
                f"unavailable-{uuid4()}",
                status=organization_status or OrganizationStatus.ACTIVE,
            )
            if membership_status is not None:
                _add_membership(
                    setup_session,
                    organization.id,
                    principal.user_id,
                    status=membership_status,
                )
            organization_id = organization.id
        else:
            organization_id = uuid4()
        setup_session.commit()

    response = client.get(f"/api/v1/organizations/{organization_id}/scans")
    missing_scope_response = client.get(f"/api/v1/organizations/{uuid4()}/scans")

    _assert_same_generic_error(response, missing_scope_response, 404)
    for sensitive_value in (str(organization_id), str(principal.user_id), "membership"):
        assert sensitive_value not in response.text


def test_cross_organization_resource_and_missing_scan_are_indistinguishable(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = _claims("cross-organization-api")
    _configure_client(client, engine, monkeypatch, claims)
    with Session(engine, expire_on_commit=False) as setup_session:
        principal = _create_local_user(setup_session, claims)
        first = _create_organization(setup_session, principal.user_id, "scope-first")
        second = _create_organization(setup_session, principal.user_id, "scope-second")
        _add_membership(setup_session, first.id, principal.user_id)
        other_scope_scan = _add_organization_scan(setup_session, second.id, principal.user_id)
        setup_session.commit()

    route = f"/api/v1/organizations/{first.id}/scans"
    cross_scope_response = client.get(f"{route}/{other_scope_scan.id}")
    missing_response = client.get(f"{route}/{uuid4()}")

    _assert_same_generic_error(cross_scope_response, missing_response, 404)


def test_membership_role_and_status_changes_apply_on_subsequent_requests(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = _claims("role-change-api")
    _, calls, _ = _configure_client(client, engine, monkeypatch, claims)
    with Session(engine, expire_on_commit=False) as setup_session:
        principal = _create_local_user(setup_session, claims)
        organization = _create_organization(setup_session, principal.user_id, "role-change-api")
        membership = _add_membership(
            setup_session,
            organization.id,
            principal.user_id,
            OrganizationRole.MEMBER,
        )
        setup_session.commit()
        membership_id = membership.id

    path = f"/api/v1/organizations/{organization.id}/scans"
    assert client.post(path).status_code == 201
    with Session(engine) as update_session:
        membership = update_session.get(OrganizationMembership, membership_id)
        assert membership is not None
        membership.role = OrganizationRole.VIEWER
        update_session.commit()

    denied = client.post(path)
    assert denied.status_code == 403
    assert denied.json() == GENERIC_ERROR
    with Session(engine) as update_session:
        membership = update_session.get(OrganizationMembership, membership_id)
        assert membership is not None
        membership.role = OrganizationRole.ADMIN
        membership.status = MembershipStatus.SUSPENDED
        update_session.commit()

    unavailable = client.post(path)
    assert unavailable.status_code == 404
    assert unavailable.json() == GENERIC_ERROR
    assert calls == [
        "create_organization_scan",
        "create_organization_scan",
        "create_organization_scan",
    ]


def test_personal_operation_rechecks_user_status_after_authentication(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = _claims("inactive-after-auth")
    _, _, factory = _configure_client(client, engine, monkeypatch, claims)
    with Session(engine, expire_on_commit=False) as setup_session:
        principal = _create_local_user(setup_session, claims)
        setup_session.commit()

    def identity_service_factory_dependency() -> Callable[[Session], Any]:
        def factory(session: Session) -> Any:
            class IdentityServiceThenSuspend:
                def resolve_authenticated_principal(
                    self,
                    verified_claims: VerifiedAccessTokenClaims,
                ) -> AuthenticatedPrincipal:
                    principal = IdentityService(
                        IdentityRepository(session)
                    ).resolve_authenticated_principal(verified_claims)
                    user = session.get(User, principal.user_id)
                    assert user is not None
                    user.status = UserStatus.SUSPENDED
                    return principal

            return IdentityServiceThenSuspend()

        return factory

    client.app.dependency_overrides[auth_dependencies.get_identity_service_factory] = (
        identity_service_factory_dependency
    )
    client.app.dependency_overrides[auth_dependencies.get_authentication_provider] = lambda: (
        StubProvider(claims)
    )
    monkeypatch.setattr(
        auth_dependencies,
        "unit_of_work",
        partial(database_session.unit_of_work, factory),
    )
    response = client.post("/api/v1/scans")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == GENERIC_ERROR
    assert str(principal.user_id) not in response.text
    assert "suspended" not in response.text


def test_identity_mapping_change_between_authentication_and_scan_is_unauthorized(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = _claims("identity-mapping-change")
    _, _, factory = _configure_client(client, engine, monkeypatch, claims)
    with Session(engine, expire_on_commit=False) as setup_session:
        principal = _create_local_user(setup_session, claims)
        setup_session.commit()

    def identity_service_factory_dependency() -> Callable[[Session], Any]:
        def factory(session: Session) -> Any:
            class IdentityServiceThenChangeMapping:
                def resolve_authenticated_principal(
                    self,
                    verified_claims: VerifiedAccessTokenClaims,
                ) -> AuthenticatedPrincipal:
                    principal = IdentityService(
                        IdentityRepository(session)
                    ).resolve_authenticated_principal(verified_claims)
                    identity = session.get(ExternalIdentity, principal.external_identity_id)
                    assert identity is not None
                    identity.subject = "different-local-subject"
                    return principal

            return IdentityServiceThenChangeMapping()

        return factory

    client.app.dependency_overrides[auth_dependencies.get_identity_service_factory] = (
        identity_service_factory_dependency
    )
    monkeypatch.setattr(
        auth_dependencies,
        "unit_of_work",
        partial(database_session.unit_of_work, factory),
    )

    response = client.get("/api/v1/scans")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == GENERIC_ERROR
    assert str(principal.external_identity_id) not in response.text


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/scans/not-a-uuid",
        "/api/v1/organizations/not-a-uuid/scans",
        f"/api/v1/organizations/{uuid4()}/scans/not-a-uuid",
    ],
)
def test_malformed_scan_uuids_are_rejected(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    claims = _claims("malformed-scan-uuid")
    _configure_client(client, engine, monkeypatch, claims)
    with Session(engine, expire_on_commit=False) as setup_session:
        _create_local_user(setup_session, claims)
        setup_session.commit()

    response = client.get(path)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "request_validation_error"


def test_scan_create_rejects_non_object_request_bodies(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = _claims("invalid-body")
    _configure_client(client, engine, monkeypatch, claims)
    with Session(engine, expire_on_commit=False) as setup_session:
        _create_local_user(setup_session, claims)
        setup_session.commit()

    for payload in ([], "scan"):
        response = client.post("/api/v1/scans", json=payload)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "request_validation_error"

    with Session(engine) as verify_session:
        assert verify_session.scalar(select(func.count()).select_from(SecurityScan)) == 0


def test_scan_routes_are_unique_and_openapi_has_no_extra_scan_fields(client: TestClient) -> None:
    openapi = client.get("/openapi.json").json()
    paths = openapi["paths"]
    expected = {
        "/api/v1/scans": {"get", "post"},
        "/api/v1/scans/{scan_id}": {"get"},
        "/api/v1/organizations/{organization_id}/scans": {"get", "post"},
        "/api/v1/organizations/{organization_id}/scans/{scan_id}": {"get"},
    }
    actual = {
        path: {method for method in operations if method in {"get", "post"}}
        for path, operations in paths.items()
        if path.startswith("/api/v1/scans")
        or path.startswith("/api/v1/organizations/{organization_id}/scans")
    }
    assert actual == expected

    response_schema = openapi["components"]["schemas"]["ScanResponse"]
    assert set(response_schema["properties"]) == {"id", "created_at"}
    for operation in (
        paths["/api/v1/scans"]["post"],
        paths["/api/v1/organizations/{organization_id}/scans"]["post"],
    ):
        assert operation["security"] == [{"HTTPBearer": []}]
        request_schema = operation["requestBody"]["content"]["application/json"]["schema"]
        if "anyOf" in request_schema:
            request_schema = next(
                item for item in request_schema["anyOf"] if item.get("type") != "null"
            )
        if "$ref" in request_schema:
            schema_name = request_schema["$ref"].rsplit("/", 1)[-1]
            request_schema = openapi["components"]["schemas"][schema_name]
        assert request_schema["additionalProperties"] is False
        assert request_schema["properties"] == {}
    for path, methods in expected.items():
        for method in methods:
            assert paths[path][method]["security"] == [{"HTTPBearer": []}]


@pytest.mark.parametrize(
    ("path", "status_code", "envelope", "challenge"),
    [
        (
            "/api/v1/health",
            200,
            {"status": "ok"},
            None,
        ),
    ],
)
def test_health_route_remains_available_after_product_routes_are_added(
    client: TestClient,
    path: str,
    status_code: int,
    envelope: dict[str, str],
    challenge: str | None,
) -> None:
    response = client.get(path)
    assert response.status_code == status_code
    assert response.json() == envelope
    assert response.headers.get("www-authenticate") == challenge


def test_authentication_configuration_failure_is_safe_on_protected_routes(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        _env_file=None,
        auth_expected_issuer=None,
        auth_expected_audience=None,
        auth_trusted_jwks_url=None,
        auth_allowed_jwt_algorithms=None,
    )
    monkeypatch.setattr(auth_dependencies, "get_settings", lambda: settings)
    auth_dependencies.get_authentication_provider.cache_clear()
    try:
        response = client.get(
            "/api/v1/scans",
            headers={"Authorization": "Bearer credential"},
        )
    finally:
        auth_dependencies.get_authentication_provider.cache_clear()

    assert response.status_code == 503
    assert response.json() == GENERIC_ERROR
    assert "credential" not in response.text
