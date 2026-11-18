from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Annotated, cast
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from threat_sentinel_api import main as api_main
from threat_sentinel_api.api import dependencies as auth_dependencies
from threat_sentinel_api.core.config import Settings
from threat_sentinel_api.db import session as database_session
from threat_sentinel_api.modules.identity.auth_errors import (
    AuthenticationVerifierFailure,
    InvalidAccessToken,
    TrustedKeySourceUnavailable,
)
from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.provider import AuthenticationProvider
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import (
    AuthenticatedPrincipal,
    VerifiedAccessTokenClaims,
)
from threat_sentinel_api.modules.identity.service import IdentityService
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership


def _claims(**overrides: object) -> VerifiedAccessTokenClaims:
    now = datetime.now(UTC)
    values: dict[str, object] = {
        "issuer": "https://issuer.example",
        "subject": "subject-123",
        "audiences": ("threat-sentinel-api",),
        "issued_at": now,
        "expires_at": now + timedelta(minutes=5),
    }
    values.update(overrides)
    return VerifiedAccessTokenClaims(**values)


class StubProvider:
    def __init__(
        self,
        claims: VerifiedAccessTokenClaims | None = None,
        error: Exception | None = None,
    ) -> None:
        self.claims = claims
        self.error = error
        self.received_tokens: list[str] = []

    async def verify_bearer_token(self, bearer_token: SecretStr) -> VerifiedAccessTokenClaims:
        self.received_tokens.append(bearer_token.get_secret_value())
        if self.error is not None:
            raise self.error
        assert self.claims is not None
        return self.claims


@pytest.fixture
def client() -> Iterator[TestClient]:
    app = FastAPI()
    app.exception_handlers.update(api_main.app.exception_handlers)

    @app.get("/protected")
    async def protected(
        principal: Annotated[
            AuthenticatedPrincipal,
            Depends(auth_dependencies.get_current_principal),
        ],
    ) -> dict[str, str]:
        return {
            "user_id": str(principal.user_id),
            "external_identity_id": str(principal.external_identity_id),
        }

    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _override_provider(client: TestClient, provider: AuthenticationProvider) -> None:
    client.app.dependency_overrides[auth_dependencies.get_authentication_provider] = lambda: (
        provider
    )


def _bind_test_unit_of_work(
    monkeypatch: pytest.MonkeyPatch,
    engine: Engine,
    sessions: list[Session] | None = None,
) -> None:
    def session_factory() -> Session:
        session = Session(engine, expire_on_commit=False)
        if sessions is not None:
            sessions.append(session)
        return session

    monkeypatch.setattr(
        auth_dependencies,
        "unit_of_work",
        partial(database_session.unit_of_work, session_factory),
    )


@pytest.fixture
def auth_provider_cache() -> Iterator[None]:
    auth_dependencies.get_authentication_provider.cache_clear()
    yield
    auth_dependencies.get_authentication_provider.cache_clear()


def test_missing_authentication_configuration_returns_safe_service_unavailable(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    auth_provider_cache: None,
) -> None:
    settings = Settings(
        _env_file=None,
        auth_expected_issuer=None,
        auth_expected_audience=None,
        auth_trusted_jwks_url=None,
        auth_allowed_jwt_algorithms=None,
    )
    monkeypatch.setattr(auth_dependencies, "get_settings", lambda: settings)
    verifier_constructor = Mock(side_effect=AssertionError("Verifier construction must not occur"))
    monkeypatch.setattr(auth_dependencies, "JwtAccessTokenVerifier", verifier_constructor)
    bearer_token = "raw-bearer-token-sentinel"

    response = client.get(
        "/protected",
        headers={"Authorization": f"Bearer {bearer_token}"},
    )

    assert response.status_code == 503
    assert response.json() == {
        "error": {
            "code": "http_error",
            "message": "The request could not be completed.",
        }
    }
    verifier_constructor.assert_not_called()
    for sensitive_value in (
        bearer_token,
        "issuer",
        "audience",
        "jwks",
        "environment",
        "secret",
    ):
        assert sensitive_value not in response.text


def test_complete_authentication_configuration_initializes_and_caches_verifier(
    monkeypatch: pytest.MonkeyPatch,
    auth_provider_cache: None,
) -> None:
    settings = Settings(
        _env_file=None,
        auth_expected_issuer="https://issuer.example",
        auth_expected_audience="threat-sentinel-api",
        auth_trusted_jwks_url="https://issuer.example/keys",
        auth_allowed_jwt_algorithms=["RS256"],
    )
    provider = Mock(spec=AuthenticationProvider)
    verifier_constructor = Mock(return_value=provider)
    monkeypatch.setattr(auth_dependencies, "get_settings", lambda: settings)
    monkeypatch.setattr(auth_dependencies, "JwtAccessTokenVerifier", verifier_constructor)

    first = auth_dependencies.get_authentication_provider()
    second = auth_dependencies.get_authentication_provider()

    assert first is provider
    assert second is provider
    verifier_constructor.assert_called_once_with(settings)


@pytest.mark.parametrize(
    "authorization",
    [
        None,
        "",
        "Bearer",
        "Bearer ",
        "Bearer token with spaces",
        "Basic token",
    ],
    ids=["missing", "empty-header", "malformed", "empty-bearer", "malformed-token", "unsupported"],
)
def test_invalid_authorization_headers_return_bearer_challenge(
    client: TestClient,
    authorization: str | None,
) -> None:
    provider = StubProvider(_claims())
    _override_provider(client, provider)
    headers = {} if authorization is None else {"Authorization": authorization}

    response = client.get("/protected", headers=headers)

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json() == {
        "error": {
            "code": "http_error",
            "message": "The request could not be completed.",
        }
    }
    assert provider.received_tokens == []


def test_missing_credentials_are_rejected_before_provider_initialization(
    client: TestClient,
) -> None:
    def provider_must_not_be_created() -> AuthenticationProvider:
        raise AssertionError("Provider should not be initialized for an unauthenticated request.")

    client.app.dependency_overrides[auth_dependencies.get_authentication_provider] = (
        provider_must_not_be_created
    )

    response = client.get("/protected")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_dependency_overrides_provider_and_identity_service_factory_without_network(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = _claims()
    principal = AuthenticatedPrincipal(
        user_id=uuid4(),
        external_identity_id=uuid4(),
        issuer=claims.issuer,
        subject=claims.subject,
    )
    provider = StubProvider(claims)
    observed_claims: list[VerifiedAccessTokenClaims] = []
    _override_provider(client, provider)

    class StubIdentityService:
        def resolve_authenticated_principal(
            self,
            verified_claims: VerifiedAccessTokenClaims,
        ) -> AuthenticatedPrincipal:
            observed_claims.append(verified_claims)
            return principal

    def service_factory(_session: Session) -> StubIdentityService:
        return StubIdentityService()

    client.app.dependency_overrides[auth_dependencies.get_identity_service_factory] = lambda: (
        service_factory
    )

    @contextmanager
    def no_database_unit_of_work() -> Iterator[Session]:
        yield cast(Session, object())

    monkeypatch.setattr(auth_dependencies, "unit_of_work", no_database_unit_of_work)
    token = "offline-test-token"

    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {
        "user_id": str(principal.user_id),
        "external_identity_id": str(principal.external_identity_id),
    }
    assert provider.received_tokens == [token]
    assert observed_claims == [claims]


@pytest.mark.parametrize(
    ("error", "expected_status"),
    [
        (InvalidAccessToken("private token-validation detail"), 401),
        (TrustedKeySourceUnavailable("private JWKS URL detail"), 503),
    ],
)
def test_verification_failures_have_safe_distinct_http_responses(
    client: TestClient,
    error: Exception,
    expected_status: int,
) -> None:
    _override_provider(client, StubProvider(error=error))

    response = client.get("/protected", headers={"Authorization": "Bearer credential"})

    assert response.status_code == expected_status
    assert "private" not in response.text
    assert "credential" not in response.text
    if expected_status == 401:
        assert response.headers["www-authenticate"] == "Bearer"
    else:
        assert "www-authenticate" not in response.headers


def test_unexpected_verifier_errors_use_safe_global_handler_and_logging(
    client: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _override_provider(
        client,
        StubProvider(error=AuthenticationVerifierFailure("private verifier internals")),
    )

    response = client.get("/protected", headers={"Authorization": "Bearer raw-token-sentinel"})

    assert response.status_code == 500
    assert "private verifier internals" not in response.text
    assert "raw-token-sentinel" not in response.text
    assert "private verifier internals" not in caplog.text
    assert "raw-token-sentinel" not in caplog.text
    assert any(
        getattr(record, "error_type", None) == "AuthenticationVerifierFailure"
        for record in caplog.records
    )


def test_successful_resolution_persists_identity_without_membership(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = _claims()
    _override_provider(client, StubProvider(claims))
    _bind_test_unit_of_work(monkeypatch, engine)
    with Session(engine) as verify_session:
        organizations_before = verify_session.scalar(select(func.count()).select_from(Organization))
        memberships_before = verify_session.scalar(
            select(func.count()).select_from(OrganizationMembership)
        )

    response = client.get("/protected", headers={"Authorization": "Bearer valid-token"})

    assert response.status_code == 200
    principal_id = UUID(response.json()["user_id"])
    with Session(engine) as verify_session:
        user = verify_session.get(User, principal_id)
        assert user is not None
        identity = verify_session.scalar(
            select(ExternalIdentity).where(
                ExternalIdentity.issuer == claims.issuer,
                ExternalIdentity.subject == claims.subject,
            )
        )
        assert identity is not None
        assert identity.user_id == principal_id
        assert (
            verify_session.scalar(select(func.count()).select_from(Organization))
            == organizations_before
        )
        assert (
            verify_session.scalar(select(func.count()).select_from(OrganizationMembership))
            == memberships_before
        )


def test_failed_provider_verification_does_not_resolve_or_provision_identity(
    client: TestClient,
    engine: Engine,
) -> None:
    _override_provider(
        client,
        StubProvider(error=InvalidAccessToken("private verification details")),
    )
    identity_service_factory = Mock()
    client.app.dependency_overrides[auth_dependencies.get_identity_service_factory] = lambda: (
        identity_service_factory
    )
    with Session(engine) as verify_session:
        users_before = verify_session.scalar(select(func.count()).select_from(User))
        identities_before = verify_session.scalar(
            select(func.count()).select_from(ExternalIdentity)
        )
        organizations_before = verify_session.scalar(select(func.count()).select_from(Organization))
        memberships_before = verify_session.scalar(
            select(func.count()).select_from(OrganizationMembership)
        )

    response = client.get("/protected", headers={"Authorization": "Bearer invalid-token"})

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert "private verification details" not in response.text
    identity_service_factory.assert_not_called()
    with Session(engine) as verify_session:
        assert verify_session.scalar(select(func.count()).select_from(User)) == users_before
        assert (
            verify_session.scalar(select(func.count()).select_from(ExternalIdentity))
            == identities_before
        )
        assert (
            verify_session.scalar(select(func.count()).select_from(Organization))
            == organizations_before
        )
        assert (
            verify_session.scalar(select(func.count()).select_from(OrganizationMembership))
            == memberships_before
        )


def test_suspended_local_user_receives_generic_unauthorized_response(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = _claims(subject="suspended-subject")
    with Session(engine, expire_on_commit=False) as setup_session:
        user = IdentityService(IdentityRepository(setup_session)).resolve_authenticated_principal(
            claims
        )
        local_user = setup_session.get(User, user.user_id)
        assert local_user is not None
        local_user.status = UserStatus.SUSPENDED
        setup_session.commit()

    _override_provider(client, StubProvider(claims))
    _bind_test_unit_of_work(monkeypatch, engine)

    response = client.get("/protected", headers={"Authorization": "Bearer valid-token"})

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert "suspended" not in response.text


def test_identity_resolution_failure_rolls_back_and_closes_session(
    client: TestClient,
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claims = _claims(subject="rolled-back-subject")
    _override_provider(client, StubProvider(claims))

    class TrackingSession(Session):
        closed_by_dependency = False

        def close(self) -> None:
            self.closed_by_dependency = True
            super().close()

    sessions: list[TrackingSession] = []

    def session_factory() -> TrackingSession:
        session = TrackingSession(engine, expire_on_commit=False)
        sessions.append(session)
        return session

    monkeypatch.setattr(
        auth_dependencies,
        "unit_of_work",
        partial(database_session.unit_of_work, session_factory),
    )

    class FailingIdentityService:
        def __init__(self, session: Session) -> None:
            self._session = session

        def resolve_authenticated_principal(
            self,
            verified_claims: VerifiedAccessTokenClaims,
        ) -> AuthenticatedPrincipal:
            IdentityService(IdentityRepository(self._session)).resolve_authenticated_principal(
                verified_claims
            )
            raise RuntimeError("private identity resolution detail")

    def service_factory(session: Session) -> FailingIdentityService:
        return FailingIdentityService(session)

    client.app.dependency_overrides[auth_dependencies.get_identity_service_factory] = lambda: (
        service_factory
    )

    response = client.get("/protected", headers={"Authorization": "Bearer valid-token"})

    assert response.status_code == 500
    assert "private identity resolution detail" not in response.text
    assert sessions[0].closed_by_dependency
    with Session(engine) as verify_session:
        assert verify_session.scalar(select(func.count()).select_from(User)) == 0
        assert verify_session.scalar(select(func.count()).select_from(ExternalIdentity)) == 0
