from collections.abc import Callable, Generator, Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from threat_sentinel_api.core.config import get_settings

SessionFactory = Callable[[], Session]


@lru_cache
def get_engine() -> Engine:
    database_url = get_settings().database_url
    if database_url is None:
        raise RuntimeError("DATABASE_URL is not configured.")

    return create_engine(
        database_url.get_secret_value(),
        pool_pre_ping=True,
    )


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_session() -> Generator[Session, None, None]:
    """Provide a request-scoped session; mutating work belongs in a unit of work."""
    with get_session_factory()() as session:
        yield session


@contextmanager
def unit_of_work(session_factory: SessionFactory | None = None) -> Iterator[Session]:
    """Commit a successful application operation, roll back failures, and close its session."""
    factory = session_factory or get_session_factory()
    session = factory()
    try:
        with session.begin():
            yield session
    finally:
        session.close()
