import os

from sqlalchemy import Engine, create_engine
from sqlalchemy.engine import URL, make_url
from sqlalchemy.exc import ArgumentError

TEST_DATABASE_ENV = "THREAT_SENTINEL_TEST_DATABASE_URL"
TEST_DATABASE_NAME = "threatsentinel_test"
TEST_DATABASE_USER = "threatsentinel_test"
LOCAL_TEST_DATABASE_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
CI_TEST_DATABASE_HOST = "localhost"


def validate_postgres_test_database_url(value: str) -> URL:
    try:
        url = make_url(value)
    except (ArgumentError, ValueError):
        raise ValueError(
            f"{TEST_DATABASE_ENV} must be a URL for the dedicated PostgreSQL test database."
        ) from None

    is_local_target = (url.host in LOCAL_TEST_DATABASE_HOSTS and url.port == 55432) or (
        url.host == CI_TEST_DATABASE_HOST and url.port == 5432
    )
    if (
        url.drivername != "postgresql+psycopg"
        or url.database != TEST_DATABASE_NAME
        or url.username != TEST_DATABASE_USER
        or not url.password
        or not is_local_target
        or url.query
    ):
        raise ValueError(
            f"{TEST_DATABASE_ENV} must target the dedicated local PostgreSQL test service."
        )

    return url


def create_postgres_test_engine(database_url: str | None = None) -> Engine:
    configured_url = database_url
    if configured_url is None:
        configured_url = os.environ.get(TEST_DATABASE_ENV)
    if configured_url is None:
        raise RuntimeError(f"{TEST_DATABASE_ENV} is required for PostgreSQL integration tests.")

    validated_url = validate_postgres_test_database_url(configured_url)
    try:
        return create_engine(validated_url, pool_pre_ping=True)
    except Exception as exc:
        raise RuntimeError(
            f"Could not create PostgreSQL test engine ({type(exc).__name__}); "
            "connection details redacted."
        ) from None
