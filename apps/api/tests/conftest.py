from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from threat_sentinel_api.db import model_registry  # noqa: F401
from threat_sentinel_api.db.base import Base
from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import VerifiedUserContext
from threat_sentinel_api.modules.identity.service import IdentityService
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.service import OrganizationService
from postgres_test_support import (
    TEST_DATABASE_NAME,
    TEST_DATABASE_USER,
    create_postgres_test_engine,
)

API_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def engine() -> Iterator[Engine]:
    test_engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(test_engine, "connect")
    def enable_foreign_keys(dbapi_connection: Any, _connection_record: Any) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(test_engine)
    yield test_engine
    Base.metadata.drop_all(test_engine)
    test_engine.dispose()


@pytest.fixture
def session(engine: Engine) -> Iterator[Session]:
    with Session(engine, expire_on_commit=False) as test_session:
        yield test_session
        test_session.rollback()


@pytest.fixture
def make_user(session: Session) -> Callable[..., User]:
    def factory(
        issuer: str = "https://identity.example",
        subject: str | None = None,
        email: str | None = None,
        email_verified: bool = False,
    ) -> User:
        context = VerifiedUserContext(
            issuer=issuer,
            subject=subject or str(uuid4()),
            email=email,
            email_verified=email_verified,
        )
        return IdentityService(IdentityRepository(session)).resolve_verified_user(context)

    return factory


@pytest.fixture
def organization_service(session: Session) -> OrganizationService:
    return OrganizationService(OrganizationRepository(session))


@pytest.fixture(scope="session")
def postgres_engine() -> Iterator[Engine]:
    test_engine = create_postgres_test_engine()
    try:
        yield test_engine
    finally:
        test_engine.dispose()


@pytest.fixture(scope="session")
def postgres_migrated_engine(postgres_engine: Engine) -> Engine:
    try:
        with postgres_engine.connect() as connection:
            identity = connection.execute(
                text(
                    "SELECT current_database(), current_user, current_setting('server_version_num')"
                )
            ).one()
    except Exception as exc:
        raise RuntimeError(
            "PostgreSQL test database identity check failed "
            f"({type(exc).__name__}); connection details redacted."
        ) from None

    if (
        identity[0] != TEST_DATABASE_NAME
        or identity[1] != TEST_DATABASE_USER
        or int(identity[2]) // 10000 != 17
    ):
        raise RuntimeError(
            "PostgreSQL integration tests require the designated PostgreSQL 17 test database."
        )

    try:
        config = Config(str(API_ROOT / "alembic.ini"))
        with postgres_engine.connect() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
    except Exception as exc:
        raise RuntimeError(
            "Alembic upgrade of PostgreSQL test database failed "
            f"({type(exc).__name__}); connection details redacted."
        ) from None
    return postgres_engine


@pytest.fixture(scope="session")
def postgres_session_factory(postgres_migrated_engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=postgres_migrated_engine, expire_on_commit=False)


@pytest.fixture
def postgres_session(postgres_session_factory: sessionmaker[Session]) -> Iterator[Session]:
    test_session = postgres_session_factory()
    try:
        yield test_session
    finally:
        test_session.close()
