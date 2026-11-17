from collections.abc import Callable

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from threat_sentinel_api.db import session as database_session
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import VerifiedUserContext
from threat_sentinel_api.modules.identity.service import IdentityService


class TrackingSession(Session):
    closed_by_test: bool

    def close(self) -> None:
        self.closed_by_test = True
        super().close()


def _session_factory(engine: Engine) -> tuple[Callable[[], Session], list[TrackingSession]]:
    sessions: list[TrackingSession] = []

    def create_session() -> TrackingSession:
        session = TrackingSession(bind=engine, expire_on_commit=False)
        session.closed_by_test = False
        sessions.append(session)
        return session

    return create_session, sessions


def test_unit_of_work_commits_success_and_closes_session(engine: Engine) -> None:
    create_session, sessions = _session_factory(engine)
    context = VerifiedUserContext(issuer="https://issuer.example", subject="committed")

    with database_session.unit_of_work(create_session) as session:
        IdentityService(IdentityRepository(session)).resolve_verified_user(context)

    with Session(engine) as verify_session:
        assert verify_session.scalar(select(func.count()).select_from(User)) == 1
        assert verify_session.scalar(select(func.count()).select_from(ExternalIdentity)) == 1
    assert sessions[0].closed_by_test


def test_unit_of_work_rolls_back_exceptions_and_closes_session(engine: Engine) -> None:
    create_session, sessions = _session_factory(engine)
    context = VerifiedUserContext(issuer="https://issuer.example", subject="rolled-back")

    with pytest.raises(RuntimeError, match="operation failed"):
        with database_session.unit_of_work(create_session) as session:
            IdentityService(IdentityRepository(session)).resolve_verified_user(context)
            raise RuntimeError("operation failed")

    with Session(engine) as verify_session:
        assert verify_session.scalar(select(func.count()).select_from(User)) == 0
        assert verify_session.scalar(select(func.count()).select_from(ExternalIdentity)) == 0
    assert sessions[0].closed_by_test


def test_request_session_closes_when_dependency_scope_ends(
    engine: Engine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    create_session, sessions = _session_factory(engine)
    monkeypatch.setattr(database_session, "get_session_factory", lambda: create_session)
    dependency = database_session.get_session()
    yielded_session = next(dependency)

    dependency.close()

    assert yielded_session is sessions[0]
    assert sessions[0].closed_by_test
