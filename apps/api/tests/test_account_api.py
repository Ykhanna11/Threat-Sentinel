from collections.abc import Iterator
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
from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.identity.schemas import VerifiedAccessTokenClaims

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
