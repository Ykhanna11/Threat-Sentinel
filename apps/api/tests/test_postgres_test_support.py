import pytest
from sqlalchemy.engine import URL

import postgres_test_support
from postgres_test_support import (
    CI_TEST_DATABASE_HOST,
    LOCAL_TEST_DATABASE_HOSTS,
    TEST_DATABASE_ENV,
    TEST_DATABASE_NAME,
    TEST_DATABASE_USER,
    create_postgres_test_engine,
    validate_postgres_test_database_url,
)


@pytest.mark.parametrize(
    ("host", "port"),
    [
        *[
            (f"[{host}]" if ":" in host else host, 55432)
            for host in sorted(LOCAL_TEST_DATABASE_HOSTS)
        ],
        (CI_TEST_DATABASE_HOST, 5432),
    ],
)
def test_validated_test_url_requires_the_dedicated_driver_and_target(host: str, port: int) -> None:
    url = validate_postgres_test_database_url(
        f"postgresql+psycopg://{TEST_DATABASE_USER}:test-secret@{host}:{port}/{TEST_DATABASE_NAME}"
    )

    assert isinstance(url, URL)
    assert url.drivername == "postgresql+psycopg"
    assert url.database == TEST_DATABASE_NAME


@pytest.mark.parametrize(
    "value",
    [
        "sqlite+pysqlite://",
        "postgresql+psycopg2://threatsentinel_test:test-secret@localhost:55432/threatsentinel_test",
        "postgresql+psycopg://threatsentinel:dev-secret@localhost:5432/threatsentinel",
        "postgresql+psycopg://threatsentinel_test:test-secret@db.example:5432/threatsentinel_test",
        "postgresql+psycopg://threatsentinel_test:test-secret@127.0.0.1:5432/threatsentinel_test",
        "postgresql+psycopg://threatsentinel_test@test-secret@localhost:55432/threatsentinel_test",
        "postgresql+psycopg://threatsentinel_test:test-secret@localhost:55432/"
        "threatsentinel_test?host=production.example",
        "not-a-database-url",
    ],
)
def test_unsafe_targets_are_rejected_without_leaking_credentials(
    value: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine_created = False

    def forbidden_engine_creation(*_args: object, **_kwargs: object) -> None:
        nonlocal engine_created
        engine_created = True
        raise AssertionError("Engine creation must follow URL validation.")

    monkeypatch.setattr(postgres_test_support, "create_engine", forbidden_engine_creation)
    with pytest.raises(ValueError) as error:
        create_postgres_test_engine(value)

    assert not engine_created
    assert "test-secret" not in str(error.value)
    assert "dev-secret" not in str(error.value)
    assert "production.example" not in str(error.value)


def test_missing_test_url_does_not_fall_back_to_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(TEST_DATABASE_ENV, raising=False)
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql+psycopg://threatsentinel_test:test-secret@localhost:55432/threatsentinel_test",
    )
    engine_created = False

    def forbidden_engine_creation(*_args: object, **_kwargs: object) -> None:
        nonlocal engine_created
        engine_created = True
        raise AssertionError("Engine creation must require the explicit test URL.")

    monkeypatch.setattr(postgres_test_support, "create_engine", forbidden_engine_creation)
    with pytest.raises(RuntimeError, match=TEST_DATABASE_ENV):
        create_postgres_test_engine()

    assert not engine_created


def test_engine_creation_errors_redact_url_and_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = (
        "postgresql+psycopg://threatsentinel_test:secret-password@localhost:55432/"
        "threatsentinel_test"
    )

    def fail_engine_creation(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"connection failed for {database_url}")

    monkeypatch.setattr(postgres_test_support, "create_engine", fail_engine_creation)

    with pytest.raises(RuntimeError) as error:
        create_postgres_test_engine(database_url)

    assert database_url not in str(error.value)
    assert "secret-password" not in str(error.value)
    assert error.value.__suppress_context__
