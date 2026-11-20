from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from threat_sentinel_api.db.session import unit_of_work
from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.targets.models import SecurityTarget, TargetVerificationChallenge
from threat_sentinel_api.modules.targets.repository import TargetRepository
from threat_sentinel_api.modules.tenants.models import Organization

pytestmark = pytest.mark.postgres_integration


def test_concurrent_challenge_consumption_succeeds_once(
    postgres_session_factory: sessionmaker[Session],
) -> None:
    with unit_of_work(postgres_session_factory) as session:
        creator = User()
        session.add(creator)
        session.flush()
        organization = Organization(
            name=f"Target consumption {uuid4()}",
            slug=f"target-consume-{uuid4()}",
            created_by_user_id=creator.id,
        )
        session.add(organization)
        session.flush()
        target = TargetRepository(session).add_target(
            organization.id,
            "concurrent.example",
            creator.id,
        )
        challenge, challenge_value = TargetRepository(session).issue_challenge(
            target,
            creator.id,
        )
        organization_id = organization.id
        target_id = target.id
        challenge_id = challenge.id
        creator_id = creator.id

    barrier = Barrier(2)

    def consume() -> bool:
        barrier.wait(timeout=5)
        with unit_of_work(postgres_session_factory) as session:
            return TargetRepository(session).consume_challenge_after_dns_proof(
                organization_id,
                target_id,
                challenge_value,
            )

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = [
                future.result(timeout=15)
                for future in (
                    executor.submit(consume),
                    executor.submit(consume),
                )
            ]
        assert sorted(results) == [False, True]

        with postgres_session_factory() as session:
            stored = session.scalar(
                select(TargetVerificationChallenge).where(
                    TargetVerificationChallenge.id == challenge_id
                )
            )
            persisted_target = session.get(SecurityTarget, target_id)
            assert stored is None
            assert persisted_target is not None
            assert persisted_target.verified_at is None
    finally:
        with unit_of_work(postgres_session_factory) as session:
            session.execute(
                delete(TargetVerificationChallenge).where(
                    TargetVerificationChallenge.organization_id == organization_id
                )
            )
            session.execute(
                delete(SecurityTarget).where(SecurityTarget.organization_id == organization_id)
            )
            session.execute(delete(Organization).where(Organization.id == organization_id))
            session.execute(delete(User).where(User.id == creator_id))
