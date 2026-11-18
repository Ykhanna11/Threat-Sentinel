from unittest.mock import Mock

from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from threat_sentinel_api.api.v1.routes import health as health_routes
from threat_sentinel_api.core.config import Settings
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
