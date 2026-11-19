import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from threat_sentinel_api.api.v1.routes import health as health_routes
from threat_sentinel_api.core.config import Settings
from threat_sentinel_api.main import app

client = TestClient(app)


def _auth_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "auth_expected_issuer": "https://issuer.example/",
        "auth_expected_audience": "threat-sentinel-api",
        "auth_trusted_jwks_url": "https://issuer.example/keys",
        "auth_allowed_jwt_algorithms": ["RS256", "ES256"],
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_settings_load_without_authentication_configuration() -> None:
    settings = Settings(_env_file=None)

    assert settings.auth_expected_issuer is None
    assert settings.auth_expected_audience is None
    assert settings.auth_trusted_jwks_url is None
    assert settings.auth_allowed_jwt_algorithms is None
    assert settings.authentication_configured is False


def test_valid_authentication_configuration_is_preserved() -> None:
    settings = _auth_settings()

    assert settings.auth_expected_issuer == "https://issuer.example/"
    assert settings.auth_expected_audience == "threat-sentinel-api"
    assert settings.auth_trusted_jwks_url == "https://issuer.example/keys"
    assert settings.auth_allowed_jwt_algorithms == ["RS256", "ES256"]
    assert settings.authentication_configured is True
    assert settings.auth_clock_skew_seconds == 30
    assert settings.auth_jwks_cache_ttl_seconds == 300
    assert settings.auth_jwks_cache_max_entries == 16
    assert settings.sensitive_rate_limit_requests == 30
    assert settings.sensitive_rate_limit_window_seconds == 60


def test_authentication_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    environment = {
        "AUTH_EXPECTED_ISSUER": "https://issuer.example/",
        "AUTH_EXPECTED_AUDIENCE": "threat-sentinel-api",
        "AUTH_TRUSTED_JWKS_URL": "https://issuer.example/keys",
        "AUTH_ALLOWED_JWT_ALGORITHMS": '["RS256"]',
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)

    settings = Settings(_env_file=None)

    assert settings.auth_expected_issuer == environment["AUTH_EXPECTED_ISSUER"]
    assert settings.auth_expected_audience == environment["AUTH_EXPECTED_AUDIENCE"]
    assert settings.auth_trusted_jwks_url == environment["AUTH_TRUSTED_JWKS_URL"]
    assert settings.auth_allowed_jwt_algorithms == ["RS256"]


@pytest.mark.parametrize(
    "provided",
    [
        {"auth_expected_issuer": "https://issuer.example"},
        {"auth_expected_audience": "api"},
        {"auth_trusted_jwks_url": "https://issuer.example/keys"},
        {"auth_allowed_jwt_algorithms": ["RS256"]},
    ],
)
def test_partial_authentication_configuration_is_rejected(provided: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **provided)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("auth_expected_issuer", ""),
        ("auth_expected_issuer", "  "),
        ("auth_expected_audience", ""),
        ("auth_expected_audience", "  "),
        ("auth_trusted_jwks_url", ""),
        ("auth_trusted_jwks_url", "  "),
    ],
)
def test_blank_authentication_values_are_rejected(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        _auth_settings(**{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("auth_expected_issuer", "not-a-url"),
        ("auth_expected_issuer", "https:///missing-host"),
        ("auth_expected_issuer", "https://issuer.example/path?query=not-allowed"),
        ("auth_expected_issuer", "https://issuer.example/path?"),
        ("auth_expected_issuer", "https://issuer.example/path#fragment"),
        ("auth_expected_issuer", "https://issuer.example/path#"),
        ("auth_expected_issuer", "https://issuer.example/%zz"),
        ("auth_trusted_jwks_url", "not-a-url"),
        ("auth_trusted_jwks_url", "https:///missing-host"),
        ("auth_trusted_jwks_url", "https://user:password@issuer.example/keys"),
        ("auth_trusted_jwks_url", "https://issuer.example:invalid/keys"),
        ("auth_trusted_jwks_url", "https://issuer.example:65536/keys"),
        ("auth_expected_audience", " audience "),
    ],
)
def test_invalid_authentication_urls_and_audience_are_rejected(
    field: str,
    value: str,
) -> None:
    with pytest.raises(ValidationError):
        _auth_settings(**{field: value})


@pytest.mark.parametrize(
    "jwks_url",
    ["http://issuer.example/keys", "http://localhost:9000/keys"],
)
def test_insecure_jwks_endpoints_are_rejected_including_localhost(jwks_url: str) -> None:
    with pytest.raises(ValidationError):
        _auth_settings(auth_trusted_jwks_url=jwks_url)


@pytest.mark.parametrize("algorithm", ["none", "HS256", "RS999"])
def test_unsupported_jwt_algorithms_are_rejected(algorithm: str) -> None:
    with pytest.raises(ValidationError):
        _auth_settings(auth_allowed_jwt_algorithms=[algorithm])


def test_empty_and_duplicate_jwt_algorithm_lists_are_rejected() -> None:
    for algorithms in ([], ["RS256", "RS256"]):
        with pytest.raises(ValidationError):
            _auth_settings(auth_allowed_jwt_algorithms=algorithms)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("auth_clock_skew_seconds", -1),
        ("auth_clock_skew_seconds", 121),
        ("auth_jwks_cache_ttl_seconds", 0),
        ("auth_jwks_cache_ttl_seconds", 3601),
        ("auth_jwks_cache_max_entries", 0),
        ("auth_jwks_cache_max_entries", 101),
    ],
)
def test_out_of_range_authentication_limits_are_rejected(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        _auth_settings(**{field: value})


def test_health_and_readiness_remain_independent_of_auth_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        health_routes,
        "get_settings",
        lambda: Settings(_env_file=None),
    )

    health_response = client.get("/api/v1/health")
    readiness_response = client.get("/api/v1/ready")

    assert health_response.status_code == 200
    assert readiness_response.status_code == 200
    assert readiness_response.json()["dependencies"]["database"] == "not_configured"
