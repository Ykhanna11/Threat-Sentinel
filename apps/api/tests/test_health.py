from unittest.mock import MagicMock, Mock

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from threat_sentinel_api.api import dependencies as auth_dependencies
from threat_sentinel_api.api.v1.routes import health as health_routes
from threat_sentinel_api.core.config import Settings
from threat_sentinel_api.modules.identity import jwks as jwks_module
from threat_sentinel_api.modules.identity import jwt_verifier as jwt_verifier_module
from threat_sentinel_api.main import app

client = TestClient(app)


def test_health_reports_liveness() -> None:
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert response.headers["x-request-id"]


def test_readiness_reports_database_as_not_configured(monkeypatch) -> None:
    monkeypatch.setattr(
        health_routes,
        "get_settings",
        lambda: Settings(_env_file=None, database_url=None),
    )

    response = client.get("/api/v1/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "dependencies": {
            "database": "not_configured",
            "authentication_configuration": "not_configured",
        },
    }


def test_readiness_reports_database_failure(monkeypatch) -> None:
    settings = Settings(
        _env_file=None,
        database_url="postgresql+psycopg://local:local@localhost:5432/threatsentinel",
    )
    engine = Mock()
    engine.connect.side_effect = OperationalError("SELECT 1", {}, OSError("unavailable"))
    monkeypatch.setattr(health_routes, "get_settings", lambda: settings)
    monkeypatch.setattr(health_routes, "get_engine", lambda: engine)

    response = client.get("/api/v1/ready")

    assert response.status_code == 503
    assert response.json() == {
        "status": "not_ready",
        "dependencies": {
            "database": "unavailable",
            "authentication_configuration": "not_configured",
        },
    }


def test_readiness_reports_complete_authentication_configuration(monkeypatch) -> None:
    settings = Settings(
        _env_file=None,
        database_url=None,
        auth_expected_issuer="https://issuer.example",
        auth_expected_audience="threat-sentinel-api",
        auth_trusted_jwks_url="https://issuer.example/keys",
        auth_allowed_jwt_algorithms=["RS256"],
    )
    monkeypatch.setattr(health_routes, "get_settings", lambda: settings)

    response = client.get("/api/v1/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "dependencies": {
            "database": "not_configured",
            "authentication_configuration": "configured",
        },
    }


def test_readiness_does_not_instantiate_authentication_infrastructure(monkeypatch) -> None:
    settings = Settings(_env_file=None, database_url=None)
    monkeypatch.setattr(health_routes, "get_settings", lambda: settings)
    authentication_dependency = Mock(
        side_effect=AssertionError("Readiness must not invoke authentication dependencies")
    )
    verifier_constructor = Mock(
        side_effect=AssertionError("Readiness must not construct a JWT verifier")
    )
    jwks_constructor = Mock(
        side_effect=AssertionError("Readiness must not instantiate JWKS infrastructure")
    )
    monkeypatch.setattr(auth_dependencies, "get_authentication_provider", authentication_dependency)
    monkeypatch.setattr(
        jwt_verifier_module,
        "JwtAccessTokenVerifier",
        verifier_constructor,
    )
    monkeypatch.setattr(jwks_module, "TrustedJwksKeyStore", jwks_constructor)

    response = client.get("/api/v1/ready")

    assert response.status_code == 200
    assert response.json()["dependencies"]["authentication_configuration"] == "not_configured"
    authentication_dependency.assert_not_called()
    verifier_constructor.assert_not_called()
    jwks_constructor.assert_not_called()


def test_readiness_reports_database_available(monkeypatch) -> None:
    settings = Settings(
        _env_file=None,
        database_url="postgresql+psycopg://local:local@localhost:5432/threatsentinel",
    )
    connection = MagicMock()
    engine = MagicMock()
    engine.connect.return_value.__enter__.return_value = connection
    monkeypatch.setattr(health_routes, "get_settings", lambda: settings)
    monkeypatch.setattr(health_routes, "get_engine", lambda: engine)

    response = client.get("/api/v1/ready")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ready",
        "dependencies": {
            "database": "available",
            "authentication_configuration": "not_configured",
        },
    }
    connection.execute.assert_called_once()
