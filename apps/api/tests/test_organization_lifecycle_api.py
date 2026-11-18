from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from functools import partial
from hashlib import sha256
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from threat_sentinel_api import main as api_main
from threat_sentinel_api.api import dependencies as auth_dependencies
from threat_sentinel_api.api.v1.routes import account as account_routes
from threat_sentinel_api.api.v1.routes import organizations as organization_routes
from threat_sentinel_api.db import session as database_session
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.schemas import VerifiedAccessTokenClaims
from threat_sentinel_api.modules.tenants.enums import (
    InvitationStatus,
    MembershipStatus,
    OrganizationRole,
    OrganizationStatus,
)
from threat_sentinel_api.modules.tenants.models import (
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
)
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.schemas import OrganizationCreate

ISSUER = "https://organization-api.example"


class StubProvider:
    def __init__(self) -> None:
        self.subject = "organization-owner"
        self.email: str | None = None
        self.email_verified = False

    async def verify_bearer_token(self, bearer_token: SecretStr) -> VerifiedAccessTokenClaims:
        assert bearer_token.get_secret_value() == "test-token"
        now = datetime.now(UTC)
        return VerifiedAccessTokenClaims(
            issuer=ISSUER,
            subject=self.subject,
            audiences=("threat-sentinel-api",),
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
            email=self.email,
            email_verified=self.email_verified if self.email is not None else None,
        )


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(api_main.app) as test_client:
        yield test_client
    api_main.app.dependency_overrides.clear()


def _configure(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[StubProvider, sessionmaker[Session]]:
    provider = StubProvider()
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    client.app.dependency_overrides[auth_dependencies.get_authentication_provider] = lambda: (
        provider
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
    monkeypatch.setattr(
        organization_routes,
        "unit_of_work",
        partial(database_session.unit_of_work, factory),
    )
    return provider, factory


def _select_identity(provider: StubProvider, subject: str, email: str | None = None) -> None:
    provider.subject = subject
    provider.email = email
    provider.email_verified = email is not None


def _identity_id(session: Session, email: str) -> UUID | None:
    return session.scalar(
        select(ExternalIdentity.id).where(
            ExternalIdentity.email == email,
            ExternalIdentity.email_verified_at.is_not(None),
        )
    )


def test_organization_creation_assigns_owner_atomically_and_hides_other_tenants(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, factory = _configure(client, engine, monkeypatch)
    created = client.post(
        "/api/v1/organizations",
        json={"name": "Acme", "slug": "acme"},
    )
    assert created.status_code == 201, created.text
    organization_id = UUID(created.json()["id"])

    with factory() as session:
        organization = session.get(Organization, organization_id)
        assert organization is not None
        assert organization.created_by_user_id is not None
        memberships = session.scalars(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id,
            )
        ).all()
        assert len(memberships) == 1
        assert memberships[0].user_id == organization.created_by_user_id
        assert memberships[0].role is OrganizationRole.OWNER
        assert memberships[0].status is MembershipStatus.ACTIVE

    duplicate = client.post(
        "/api/v1/organizations",
        json={"name": "Another", "slug": "acme"},
    )
    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["message"] == "The request could not be completed."
    second_organization = client.post(
        "/api/v1/organizations",
        json={"name": "Second", "slug": "second"},
    )
    assert second_organization.status_code == 201
    slug_conflict = client.patch(
        f"/api/v1/organizations/{second_organization.json()['id']}",
        json={"slug": "acme"},
    )
    assert slug_conflict.status_code == 409
    with factory() as session:
        persisted_second = session.get(Organization, UUID(second_organization.json()["id"]))
        assert persisted_second is not None
        assert persisted_second.slug == "second"

    _select_identity(provider, "organization-outsider")
    assert client.get(f"/api/v1/organizations/{organization_id}/members").status_code == 404
    assert (
        client.patch(
            f"/api/v1/organizations/{organization_id}",
            json={"name": "Unauthorized"},
        ).status_code
        == 404
    )
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(Organization)) == 2


def test_invitation_is_hashed_single_use_and_bound_to_the_exact_verified_identity(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, factory = _configure(client, engine, monkeypatch)
    organization = client.post(
        "/api/v1/organizations",
        json={"name": "Invitations", "slug": "invitation-org"},
    ).json()
    organization_id = UUID(organization["id"])

    _select_identity(provider, "intended-user", "person@example.test")
    assert client.get("/api/v1/account/profile").status_code == 200
    with factory() as session:
        intended_identity_id = _identity_id(session, "person@example.test")
        assert intended_identity_id is not None

    _select_identity(provider, "organization-owner")
    created = client.post(
        f"/api/v1/organizations/{organization_id}/invitations",
        json={"email": " Person@Example.Test ", "role": "viewer"},
    )
    assert created.status_code == 201, created.text
    assert created.headers["cache-control"] == "no-store"
    invitation_data = created.json()
    token = invitation_data["token"]
    invitation_id = UUID(invitation_data["id"])
    with factory() as session:
        invitation = session.get(OrganizationInvitation, invitation_id)
        assert invitation is not None
        assert invitation.token_hash == sha256(token.encode("ascii")).hexdigest()
        assert invitation.token_hash != token
        assert invitation.intended_identity_id == intended_identity_id

    _select_identity(provider, "different-user", "person@example.test")
    rejected = client.post("/api/v1/organization-invitations/accept", json={"token": token})
    assert rejected.status_code == 404
    with factory() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(OrganizationMembership)
                .where(
                    OrganizationMembership.organization_id == organization_id,
                    OrganizationMembership.user_id
                    == select(User.id)
                    .join(ExternalIdentity)
                    .where(
                        ExternalIdentity.subject == "different-user",
                    )
                    .scalar_subquery(),
                )
            )
            == 0
        )

    _select_identity(provider, "intended-user", "person@example.test")
    accepted = client.post("/api/v1/organization-invitations/accept", json={"token": token})
    replayed = client.post("/api/v1/organization-invitations/accept", json={"token": token})
    assert accepted.status_code == 200
    assert accepted.json() == {
        "organization_id": str(organization_id),
        "role": "viewer",
        "status": "active",
    }
    assert replayed.status_code == 404
    with factory() as session:
        invitation = session.get(OrganizationInvitation, invitation_id)
        assert invitation is not None
        assert invitation.status is InvitationStatus.ACCEPTED


def test_role_checks_ownership_transfer_and_owner_lifecycle(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, factory = _configure(client, engine, monkeypatch)
    organization = client.post(
        "/api/v1/organizations",
        json={"name": "Lifecycle", "slug": "lifecycle-org"},
    ).json()
    organization_id = UUID(organization["id"])

    _select_identity(provider, "new-owner", "new-owner@example.test")
    assert client.get("/api/v1/account/profile").status_code == 200
    _select_identity(provider, "organization-owner")
    owner_invite = client.post(
        f"/api/v1/organizations/{organization_id}/invitations",
        json={"email": "new-owner@example.test", "role": "member"},
    )
    assert owner_invite.status_code == 201
    token = owner_invite.json()["token"]
    _select_identity(provider, "new-owner", "new-owner@example.test")
    assert (
        client.post(
            "/api/v1/organization-invitations/accept",
            json={"token": token},
        ).status_code
        == 200
    )

    with factory() as session:
        owner_membership = session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.role == OrganizationRole.OWNER,
            )
        )
        new_membership = session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.role == OrganizationRole.MEMBER,
            )
        )
        assert owner_membership is not None and new_membership is not None
        owner_membership_id = str(owner_membership.id)
        new_membership_id = str(new_membership.id)

    self_change = client.patch(
        f"/api/v1/organizations/{organization_id}/members/{new_membership_id}",
        json={"role": "owner"},
    )
    assert self_change.status_code == 403
    _select_identity(provider, "organization-owner")
    transfer = client.post(
        f"/api/v1/organizations/{organization_id}/ownership-transfer",
        json={"membership_id": new_membership_id},
    )
    assert transfer.status_code == 200
    with factory() as session:
        active_owners = session.scalars(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.role == OrganizationRole.OWNER,
                OrganizationMembership.status == MembershipStatus.ACTIVE,
            )
        ).all()
        assert len(active_owners) == 1
        assert str(active_owners[0].id) == new_membership_id

    _select_identity(provider, "organization-owner")
    assert client.post(f"/api/v1/organizations/{organization_id}/suspend").status_code == 403
    assert owner_membership_id != new_membership_id

    _select_identity(provider, "pending-user", "pending@example.test")
    assert client.get("/api/v1/account/profile").status_code == 200
    _select_identity(provider, "new-owner", "new-owner@example.test")
    pending_invite = client.post(
        f"/api/v1/organizations/{organization_id}/invitations",
        json={"email": "pending@example.test", "role": "viewer"},
    )
    assert pending_invite.status_code == 201
    suspended = client.post(f"/api/v1/organizations/{organization_id}/suspend")
    assert suspended.status_code == 200
    assert suspended.json()["status"] == OrganizationStatus.SUSPENDED
    assert client.get(f"/api/v1/organizations/{organization_id}/members").status_code == 404
    with factory() as session:
        organization_row = session.get(Organization, organization_id)
        assert organization_row is not None
        assert organization_row.status is OrganizationStatus.SUSPENDED
        pending_row = session.get(OrganizationInvitation, UUID(pending_invite.json()["id"]))
        assert pending_row is not None
        assert pending_row.status is InvitationStatus.REVOKED

    reactivated = client.post(f"/api/v1/organizations/{organization_id}/reactivate")
    assert reactivated.status_code == 200
    assert reactivated.json()["status"] == OrganizationStatus.ACTIVE
    _select_identity(provider, "pending-user", "pending@example.test")
    assert (
        client.post(
            "/api/v1/organization-invitations/accept",
            json={"token": pending_invite.json()["token"]},
        ).status_code
        == 404
    )


def test_admin_cannot_grant_admin_or_change_owner_and_input_is_strict(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, factory = _configure(client, engine, monkeypatch)
    organization = client.post(
        "/api/v1/organizations",
        json={"name": "Roles", "slug": "role-policy"},
    ).json()
    organization_id = UUID(organization["id"])

    _select_identity(provider, "admin-user", "admin@example.test")
    assert client.get("/api/v1/account/profile").status_code == 200
    _select_identity(provider, "organization-owner")
    invite = client.post(
        f"/api/v1/organizations/{organization_id}/invitations",
        json={"email": "admin@example.test", "role": "admin"},
    )
    assert invite.status_code == 201
    _select_identity(provider, "admin-user", "admin@example.test")
    assert (
        client.post(
            "/api/v1/organization-invitations/accept",
            json={"token": invite.json()["token"]},
        ).status_code
        == 200
    )

    _select_identity(provider, "viewer-user", "viewer@example.test")
    assert client.get("/api/v1/account/profile").status_code == 200
    _select_identity(provider, "admin-user", "admin@example.test")
    cannot_grant_admin = client.post(
        f"/api/v1/organizations/{organization_id}/invitations",
        json={"email": "viewer@example.test", "role": "admin"},
    )
    owner_grant = client.post(
        f"/api/v1/organizations/{organization_id}/invitations",
        json={"email": "viewer@example.test", "role": "owner"},
    )
    assert cannot_grant_admin.status_code == 403
    assert owner_grant.status_code == 422

    permitted_invitation = client.post(
        f"/api/v1/organizations/{organization_id}/invitations",
        json={"email": "viewer@example.test", "role": "member"},
    )
    assert permitted_invitation.status_code == 201
    _select_identity(provider, "viewer-user", "viewer@example.test")
    assert (
        client.post(
            "/api/v1/organization-invitations/accept",
            json={"token": permitted_invitation.json()["token"]},
        ).status_code
        == 200
    )

    with factory() as session:
        owner_membership = session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.role == OrganizationRole.OWNER,
            )
        )
        viewer_membership = session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.role == OrganizationRole.MEMBER,
            )
        )
        assert owner_membership is not None and viewer_membership is not None
        owner_membership_id = owner_membership.id
        viewer_membership_id = viewer_membership.id

    _select_identity(provider, "admin-user", "admin@example.test")
    changed_member = client.patch(
        f"/api/v1/organizations/{organization_id}/members/{viewer_membership_id}",
        json={"role": "viewer"},
    )
    changed_owner = client.patch(
        f"/api/v1/organizations/{organization_id}/members/{owner_membership_id}",
        json={"status": "removed"},
    )
    assert changed_member.status_code == 200
    assert changed_member.json()["role"] == "viewer"
    assert changed_owner.status_code == 403


def test_revoked_expired_and_malformed_invitation_tokens_are_rejected(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider, factory = _configure(client, engine, monkeypatch)
    organization = client.post(
        "/api/v1/organizations",
        json={"name": "Token states", "slug": "token-states"},
    ).json()
    organization_id = UUID(organization["id"])
    _select_identity(provider, "invited-user", "invited@example.test")
    assert client.get("/api/v1/account/profile").status_code == 200

    _select_identity(provider, "organization-owner")
    revoked_invite = client.post(
        f"/api/v1/organizations/{organization_id}/invitations",
        json={"email": "invited@example.test", "role": "member"},
    )
    assert revoked_invite.status_code == 201
    revoked_id = UUID(revoked_invite.json()["id"])
    assert (
        client.delete(
            f"/api/v1/organizations/{organization_id}/invitations/{revoked_id}"
        ).status_code
        == 204
    )

    _select_identity(provider, "invited-user", "invited@example.test")
    revoked_acceptance = client.post(
        "/api/v1/organization-invitations/accept",
        json={"token": revoked_invite.json()["token"]},
    )
    malformed = client.post(
        "/api/v1/organization-invitations/accept",
        json={"token": "not a valid token 🚫"},
    )
    assert revoked_acceptance.status_code == 404
    assert malformed.status_code == 422

    _select_identity(provider, "organization-owner")
    expired_invite = client.post(
        f"/api/v1/organizations/{organization_id}/invitations",
        json={"email": "invited@example.test", "role": "viewer"},
    )
    assert expired_invite.status_code == 201
    expired_id = UUID(expired_invite.json()["id"])
    with factory() as session, session.begin():
        invitation = session.get(OrganizationInvitation, expired_id)
        assert invitation is not None
        now = datetime.now(UTC)
        invitation.created_at = now - timedelta(days=10)
        invitation.expires_at = now - timedelta(days=1)

    _select_identity(provider, "invited-user", "invited@example.test")
    expired_acceptance = client.post(
        "/api/v1/organization-invitations/accept",
        json={"token": expired_invite.json()["token"]},
    )
    assert expired_acceptance.status_code == 404
    with factory() as session:
        revoked = session.get(OrganizationInvitation, revoked_id)
        expired = session.get(OrganizationInvitation, expired_id)
        assert revoked is not None and revoked.status is InvitationStatus.REVOKED
        assert expired is not None and expired.status is InvitationStatus.EXPIRED


def test_failed_initial_membership_insert_rolls_back_organization(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(client, engine, monkeypatch)
    assert client.get("/api/v1/account/profile").status_code == 200

    def fail_after_organization_insert(
        repository: OrganizationRepository,
        details: OrganizationCreate,
        owner: User,
    ) -> Organization:
        organization = Organization(
            name="Rollback",
            slug="rollback",
            created_by=owner,
        )
        repository._session.add(organization)
        repository._session.flush()
        raise RuntimeError("initial owner insert failed")

    monkeypatch.setattr(
        OrganizationRepository,
        "create_with_owner",
        fail_after_organization_insert,
    )
    with pytest.raises(RuntimeError, match="initial owner insert failed"):
        client.post(
            "/api/v1/organizations",
            json={"name": "Rollback", "slug": "rollback"},
        )

    with sessionmaker(bind=engine)() as session:
        assert session.scalar(select(func.count()).select_from(Organization)) == 0
        assert session.scalar(select(func.count()).select_from(OrganizationMembership)) == 0
