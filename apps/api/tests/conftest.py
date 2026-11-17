from collections.abc import Callable, Iterator
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from threat_sentinel_api.db import model_registry  # noqa: F401
from threat_sentinel_api.db.base import Base
from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import VerifiedUserContext
from threat_sentinel_api.modules.identity.service import IdentityService
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.service import OrganizationService


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
