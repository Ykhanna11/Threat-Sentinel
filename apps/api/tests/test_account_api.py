from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import partial

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from threat_sentinel_api import main as api_main
from threat_sentinel_api.api import dependencies as auth_dependencies
from threat_sentinel_api.api.v1.routes import account as account_routes
from threat_sentinel_api.db import session as database_session
from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.audit.models import SecurityAuditEvent
from threat_sentinel_api.modules.identity.schemas import (
    AuthenticatedPrincipal,
    VerifiedAccessTokenClaims,
)
from threat_sentinel_api.modules.tenants.enums import MembershipStatus, OrganizationRole
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership

ISSUER = "https://account-api.example"


class StubProvider:
    def __init__(self, claims: VerifiedAccessTokenClaims) -> None:
        self.claims = claims

    async def verify_bearer_token(self, bearer_token: SecretStr) -> VerifiedAccessTokenClaims:
        assert bearer_token.get_secret_value() == "test-token"
        return self.claims


def _claims(subject: str) -> VerifiedAccessTokenClaims:
    now = datetime.now(UTC)
    return VerifiedAccessTokenClaims(
        issuer=ISSUER,
        subject=subject,
        audiences=("threat-sentinel-api",),
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(api_main.app, raise_server_exceptions=False) as test_client:
        yield test_client
    api_main.app.dependency_overrides.clear()


def _configure(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    subject: str,
) -> sessionmaker[Session]:
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    client.app.dependency_overrides[auth_dependencies.get_authentication_provider] = lambda: (
        StubProvider(_claims(subject))
    )
    client.headers["Authorization"] = "Bearer test-token"
    monkeypatch.setattr(
        auth_dependencies,
        "unit_of_work",
        partial(database_session.unit_of_work, factory),
    )
    monkeypatch.setattr(
        account_routes,
        "unit_of_work",
        partial(database_session.unit_of_work, factory),
    )
    return factory


def test_profile_onboards_verified_identity_idempotently_and_updates_only_display_name(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _configure(client, engine, monkeypatch, "profile-owner")

    first = client.get("/api/v1/account/profile")
    second = client.get("/api/v1/account/profile")
    updated = client.patch(
        "/api/v1/account/profile",
        json={"display_name": "  A. User  "},
    )
    current = client.get("/api/v1/account/profile")

    assert first.status_code == second.status_code == 200
    assert first.json()["display_name"] is None
    assert updated.status_code == 200
    assert updated.json()["display_name"] == "A. User"
    assert current.json()["display_name"] == "A. User"
    assert set(current.json()) == {"display_name", "created_at"}
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(User)) == 1


def test_profile_is_scoped_to_the_authenticated_identity_and_rejects_protected_fields(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _configure(client, engine, monkeypatch, "first-account")
    assert (
        client.patch(
            "/api/v1/account/profile",
            json={"display_name": "First"},
        ).status_code
        == 200
    )

    client.app.dependency_overrides[auth_dependencies.get_authentication_provider] = lambda: (
        StubProvider(_claims("second-account"))
    )
    second = client.get("/api/v1/account/profile")
    assert second.status_code == 200
    assert second.json()["display_name"] is None

    for payload in (
        {"user_id": "00000000-0000-0000-0000-000000000001"},
        {"status": "deactivated"},
        {"role": "owner"},
        {"display_name": "Second", "user_id": "00000000-0000-0000-0000-000000000001"},
    ):
        response = client.patch("/api/v1/account/profile", json=payload)
        assert response.status_code == 422

    assert (
        client.patch(
            "/api/v1/account/profile",
            json={"display_name": "Second"},
        ).status_code
        == 200
    )
    with factory() as session:
        names = session.scalars(select(User.display_name).order_by(User.id)).all()
    assert sorted(names) == ["First", "Second"]


@pytest.mark.parametrize(
    "payload",
    [
        {"display_name": ""},
        {"display_name": "  "},
        {"display_name": "x" * 101},
        {"display_name": 7},
        {},
    ],
)
def test_profile_update_rejects_invalid_input(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
) -> None:
    _configure(client, engine, monkeypatch, "invalid-profile")
    response = client.patch("/api/v1/account/profile", json=payload)

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "request_validation_error"


def test_deactivation_requires_explicit_confirmation_and_preserves_account_history(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _configure(client, engine, monkeypatch, "deactivation-account")
    assert client.get("/api/v1/account/profile").status_code == 200

    for payload in (
        {"confirmation": "deactivate"},
        {"confirmation": "DEACTIVATE", "user_id": "00000000-0000-0000-0000-000000000001"},
        {"confirmation": "DEACTIVATE", "status": "active"},
    ):
        invalid = client.post("/api/v1/account/deactivate", json=payload)
        assert invalid.status_code == 422
    with factory() as session:
        user = session.scalar(select(User))
        assert user is not None and user.status is UserStatus.ACTIVE

    response = client.post("/api/v1/account/deactivate", json={"confirmation": "DEACTIVATE"})

    assert response.status_code == 204
    assert response.content == b""
    profile = client.get("/api/v1/account/profile")
    repeated = client.post(
        "/api/v1/account/deactivate",
        json={"confirmation": "DEACTIVATE"},
    )
    assert profile.status_code == repeated.status_code == 401
    assert profile.headers["www-authenticate"] == "Bearer"
    assert (
        profile.json()
        == repeated.json()
        == {
            "error": {
                "code": "http_error",
                "message": "The request could not be completed.",
            }
        }
    )

    with factory() as session:
        user = session.scalar(select(User))
        identity = session.scalar(select(ExternalIdentity))
        assert user is not None and user.status is UserStatus.DEACTIVATED
        assert identity is not None and identity.user_id == user.id

    openapi = client.get("/openapi.json").json()
    operation = openapi["paths"]["/api/v1/account/deactivate"]["post"]
    request_schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert request_schema["$ref"].endswith("/AccountDeactivationRequest")
    assert "204" in operation["responses"]

    with factory() as session:
        event = session.scalar(
            select(SecurityAuditEvent).where(SecurityAuditEvent.action == "account.deactivated")
        )
        assert event is not None
        assert event.actor_user_id == user.id
        assert event.request_id


def test_deactivation_preserves_active_member_membership(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _configure(client, engine, monkeypatch, "member-account")
    assert client.get("/api/v1/account/profile").status_code == 200
    with factory() as session, session.begin():
        user = session.scalar(select(User))
        assert user is not None
        organization = Organization(
            name="Member organization",
            slug="member-organization",
            created_by_user_id=user.id,
        )
        session.add(organization)
        session.flush()
        membership = OrganizationMembership(
            organization_id=organization.id,
            user_id=user.id,
            role=OrganizationRole.MEMBER,
            status=MembershipStatus.ACTIVE,
        )
        session.add(membership)
        session.flush()
        membership_id = membership.id

    response = client.post(
        "/api/v1/account/deactivate",
        json={"confirmation": "DEACTIVATE"},
    )

    assert response.status_code == 204
    with factory() as session:
        user = session.scalar(select(User))
        membership = session.get(OrganizationMembership, membership_id)
        assert user is not None and user.status is UserStatus.DEACTIVATED
        assert membership is not None
        assert membership.role is OrganizationRole.MEMBER
        assert membership.status is MembershipStatus.ACTIVE


def test_deactivation_rejects_last_active_owner_with_generic_conflict(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _configure(client, engine, monkeypatch, "sole-owner")
    assert client.get("/api/v1/account/profile").status_code == 200
    with factory() as session, session.begin():
        owner = session.scalar(select(User))
        assert owner is not None
        organization = Organization(
            name="Sole owner organization",
            slug="sole-owner-organization",
            created_by_user_id=owner.id,
        )
        session.add(organization)
        session.flush()
        session.add(
            OrganizationMembership(
                organization_id=organization.id,
                user_id=owner.id,
                role=OrganizationRole.OWNER,
                status=MembershipStatus.ACTIVE,
            )
        )

    response = client.post(
        "/api/v1/account/deactivate",
        json={"confirmation": "DEACTIVATE"},
    )

    assert response.status_code == 409
    assert response.json() == {
        "error": {
            "code": "http_error",
            "message": "The request could not be completed.",
        }
    }
    with factory() as session:
        owner = session.scalar(select(User))
        assert owner is not None and owner.status is UserStatus.ACTIVE


@pytest.mark.parametrize(
    ("other_owner_status", "expected_status"),
    [
        (UserStatus.ACTIVE, 204),
        (UserStatus.SUSPENDED, 409),
    ],
)
def test_deactivation_requires_another_active_user_owner_and_preserves_membership(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
    other_owner_status: UserStatus,
    expected_status: int,
) -> None:
    factory = _configure(client, engine, monkeypatch, "shared-owner")
    assert client.get("/api/v1/account/profile").status_code == 200
    with factory() as session, session.begin():
        owner = session.scalar(select(User))
        assert owner is not None
        other_owner = User()
        other_owner.status = other_owner_status
        session.add(
            ExternalIdentity(
                user=other_owner,
                issuer=ISSUER,
                subject="other-active-owner",
            )
        )
        organization = Organization(
            name="Shared owner organization",
            slug="shared-owner-organization",
            created_by_user_id=owner.id,
        )
        session.add(organization)
        session.flush()
        session.add_all(
            [
                OrganizationMembership(
                    organization_id=organization.id,
                    user_id=owner.id,
                    role=OrganizationRole.OWNER,
                    status=MembershipStatus.ACTIVE,
                ),
                OrganizationMembership(
                    organization_id=organization.id,
                    user_id=other_owner.id,
                    role=OrganizationRole.OWNER,
                    status=MembershipStatus.ACTIVE,
                ),
            ]
        )

    response = client.post(
        "/api/v1/account/deactivate",
        json={"confirmation": "DEACTIVATE"},
    )

    assert response.status_code == expected_status
    with factory() as session:
        owner = session.scalar(
            select(User)
            .join(ExternalIdentity)
            .where(
                ExternalIdentity.subject == "shared-owner",
            )
        )
        memberships = session.scalars(select(OrganizationMembership)).all()
        expected_owner_status = (
            UserStatus.DEACTIVATED if expected_status == 204 else UserStatus.ACTIVE
        )
        assert owner is not None and owner.status is expected_owner_status
        assert len(memberships) == 2
        assert all(membership.status is MembershipStatus.ACTIVE for membership in memberships)


def test_account_export_is_self_scoped_and_does_not_return_secrets(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _configure(client, engine, monkeypatch, "export-owner")
    assert client.get("/api/v1/account/profile").status_code == 200
    with factory() as session, session.begin():
        user = session.scalar(
            select(User).join(ExternalIdentity).where(ExternalIdentity.subject == "export-owner")
        )
        assert user is not None
        organization = Organization(
            name="Export organization",
            slug="export-organization",
            created_by_user_id=user.id,
        )
        session.add(organization)
        session.flush()
        session.add(
            OrganizationMembership(
                organization_id=organization.id,
                user_id=user.id,
                role=OrganizationRole.OWNER,
                status=MembershipStatus.ACTIVE,
            )
        )

    response = client.get("/api/v1/account/export")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "active"
    assert len(payload["memberships"]) == 1
    assert "token" not in payload
    assert "email" not in payload
    assert "external_identity_ids" not in payload
    assert "password" not in payload
    assert "credential" not in payload
    assert "invitation" not in payload


def test_account_export_rejects_cross_user_principal_and_concurrent_deactivation(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _configure(client, engine, monkeypatch, "export-user-a")
    assert client.get("/api/v1/account/profile").status_code == 200
    with factory() as session, session.begin():
        first = session.scalar(
            select(User).join(ExternalIdentity).where(ExternalIdentity.subject == "export-user-a")
        )
        assert first is not None
        first.status = UserStatus.DEACTIVATED

    response = client.get("/api/v1/account/export")
    assert response.status_code == 401
    with factory() as session:
        user = session.scalar(
            select(User).join(ExternalIdentity).where(ExternalIdentity.subject == "export-user-a")
        )
        assert user is not None
        event = session.scalar(
            select(SecurityAuditEvent).where(
                SecurityAuditEvent.action == "account.export_denied",
                SecurityAuditEvent.actor_user_id == user.id,
            )
        )
        assert event is not None
        assert event.outcome == "failure"
        assert event.details == {"reason": "inactive_account"}


def test_account_export_failure_records_safe_event_for_verified_principal(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _configure(client, engine, monkeypatch, "export-failure-user")
    assert client.get("/api/v1/account/profile").status_code == 200
    with factory() as session:
        identity = session.scalar(
            select(ExternalIdentity).where(ExternalIdentity.subject == "export-failure-user")
        )
        assert identity is not None
        principal = AuthenticatedPrincipal(
            user_id=identity.user_id,
            external_identity_id=identity.id,
            issuer=identity.issuer,
            subject=identity.subject,
            email=identity.email,
            email_verified=identity.email_verified_at is not None,
        )
        user = session.get(User, identity.user_id)
        assert user is not None
        user.status = UserStatus.DEACTIVATED
        session.commit()

    client.app.dependency_overrides[auth_dependencies.get_current_principal] = lambda: principal
    original_unit_of_work = account_routes.unit_of_work
    transaction_events: list[str] = []

    @contextmanager
    def instrumented_unit_of_work() -> Iterator[Session]:
        uow_number = len(transaction_events) // 2 + 1
        transaction_events.append(f"uow{uow_number}:enter")
        try:
            with original_unit_of_work() as session:
                yield session
        except BaseException:
            transaction_events.append(f"uow{uow_number}:rollback")
            raise
        else:
            transaction_events.append(f"uow{uow_number}:commit")

    monkeypatch.setattr(account_routes, "unit_of_work", instrumented_unit_of_work)
    response = client.get("/api/v1/account/export")

    assert response.status_code == 401
    assert transaction_events == [
        "uow1:enter",
        "uow1:rollback",
        "uow2:enter",
        "uow2:commit",
    ]
    with factory() as session:
        event = session.scalar(
            select(SecurityAuditEvent).where(
                SecurityAuditEvent.action == "account.export_denied",
                SecurityAuditEvent.actor_user_id == principal.user_id,
            )
        )
        assert event is not None
        assert event.outcome == "failure"
        assert event.organization_id is None
        assert event.target_type == "user"
        assert event.target_id == principal.user_id
        assert event.details == {"reason": "inactive_account"}
        serialized = repr(event.details).lower()
        assert all(
            secret not in serialized
            for secret in ("password", "token", "credential", "invitation", "email")
        )


def test_account_export_excludes_cross_user_and_cross_tenant_memberships(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = _configure(client, engine, monkeypatch, "export-owner-isolated")
    assert client.get("/api/v1/account/profile").status_code == 200
    with factory() as session, session.begin():
        owner = session.scalar(
            select(User)
            .join(ExternalIdentity)
            .where(ExternalIdentity.subject == "export-owner-isolated")
        )
        other = User()
        session.add(other)
        session.flush()
        own_org = Organization(
            name="Own tenant",
            slug="own-export-tenant",
            created_by_user_id=owner.id,
        )
        other_org = Organization(
            name="Other tenant",
            slug="other-export-tenant",
            created_by_user_id=other.id,
        )
        session.add_all([own_org, other_org])
        session.flush()
        session.add_all(
            [
                OrganizationMembership(
                    organization_id=own_org.id,
                    user_id=owner.id,
                    role=OrganizationRole.OWNER,
                    status=MembershipStatus.ACTIVE,
                ),
                OrganizationMembership(
                    organization_id=other_org.id,
                    user_id=other.id,
                    role=OrganizationRole.OWNER,
                    status=MembershipStatus.ACTIVE,
                ),
            ]
        )

    response = client.get("/api/v1/account/export")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["memberships"]) == 1
    assert payload["memberships"][0]["organization_id"] != str(other_org.id)
