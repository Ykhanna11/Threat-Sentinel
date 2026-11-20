from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from threading import Barrier, Event
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from threat_sentinel_api.db.session import unit_of_work
from threat_sentinel_api.modules.audit.models import SecurityAuditEvent
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import (
    AuthenticatedPrincipal,
    VerifiedUserContext,
)
from threat_sentinel_api.modules.identity.service import IdentityService
from threat_sentinel_api.modules.targets.models import SecurityTarget, TargetVerificationChallenge
from threat_sentinel_api.modules.targets.service import TargetService, TargetVerificationFailed
from threat_sentinel_api.modules.tenants.enums import MembershipStatus, OrganizationRole
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership

pytestmark = pytest.mark.postgres_integration

_ISSUER = "https://target-postgres-tests.example"


class BarrierDNSVerifier:
    def __init__(self, barrier: Barrier) -> None:
        self._barrier = barrier

    def verify_challenge(self, hostname: str, expected_hash: str) -> None:
        assert hostname == "concurrent.example"
        assert len(expected_hash) == 64
        self._barrier.wait(timeout=5)


class PausedDNSVerifier:
    def __init__(self, started: Event, continue_lookup: Event) -> None:
        self._started = started
        self._continue_lookup = continue_lookup

    def verify_challenge(self, hostname: str, expected_hash: str) -> None:
        assert hostname == "concurrent.example"
        assert len(expected_hash) == 64
        self._started.set()
        if not self._continue_lookup.wait(timeout=10):
            raise TimeoutError("DNS fixture was not released.")


def create_target(
    session_factory: sessionmaker[Session],
    verifier: BarrierDNSVerifier | PausedDNSVerifier,
) -> tuple[TargetService, AuthenticatedPrincipal, UUID, UUID, str, UUID]:
    subject = str(uuid4())
    with unit_of_work(session_factory) as session:
        user = IdentityService(IdentityRepository(session)).resolve_verified_user(
            VerifiedUserContext(
                issuer=_ISSUER,
                subject=subject,
            )
        )
        identity_id = session.scalar(
            select(ExternalIdentity.id).where(ExternalIdentity.user_id == user.id)
        )
        assert identity_id is not None
        organization = Organization(
            name=f"Target verification {uuid4()}",
            slug=f"target-verify-{uuid4()}",
            created_by_user_id=user.id,
        )
        session.add(organization)
        session.flush()
        session.add(
            OrganizationMembership(
                organization_id=organization.id,
                user_id=user.id,
                role=OrganizationRole.OWNER,
                status=MembershipStatus.ACTIVE,
            )
        )
        principal = AuthenticatedPrincipal(
            user_id=user.id,
            external_identity_id=identity_id,
            issuer=_ISSUER,
            subject=subject,
        )
        organization_id = organization.id
        user_id = user.id

    service = TargetService(session_factory, dns_verifier=verifier)
    issued = service.create_organization_target(
        principal,
        organization_id,
        "concurrent.example",
    )
    return (
        service,
        principal,
        organization_id,
        issued.target_id,
        issued.challenge_value,
        user_id,
    )


def clean_target(
    session_factory: sessionmaker[Session],
    organization_id: UUID,
    user_id: UUID,
) -> None:
    with unit_of_work(session_factory) as session:
        session.execute(
            delete(SecurityAuditEvent).where(SecurityAuditEvent.organization_id == organization_id)
        )
        session.execute(
            delete(TargetVerificationChallenge).where(
                TargetVerificationChallenge.organization_id == organization_id
            )
        )
        session.execute(
            delete(SecurityTarget).where(SecurityTarget.organization_id == organization_id)
        )
        session.execute(
            delete(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id
            )
        )
        session.execute(delete(Organization).where(Organization.id == organization_id))
        session.execute(delete(ExternalIdentity).where(ExternalIdentity.user_id == user_id))
        session.execute(delete(User).where(User.id == user_id))


def test_concurrent_dns_verification_succeeds_once(
    postgres_session_factory: sessionmaker[Session],
) -> None:
    barrier = Barrier(2)
    (
        service,
        principal,
        organization_id,
        target_id,
        _challenge_value,
        user_id,
    ) = create_target(postgres_session_factory, BarrierDNSVerifier(barrier))

    def verify() -> bool:
        service.verify_organization_target(principal, organization_id, target_id)
        return True

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(verify), executor.submit(verify)]
            outcomes = []
            for future in futures:
                try:
                    outcomes.append(future.result(timeout=15))
                except TargetVerificationFailed:
                    outcomes.append(False)
        assert sorted(outcomes) == [False, True]

        with postgres_session_factory() as session:
            target = session.get(SecurityTarget, target_id)
            assert target is not None
            assert target.verified_at is not None
            assert (
                session.scalar(
                    select(TargetVerificationChallenge.id).where(
                        TargetVerificationChallenge.target_id == target_id
                    )
                )
                is None
            )
    finally:
        clean_target(postgres_session_factory, organization_id, user_id)


def test_challenge_rotation_during_dns_invalidates_verification(
    postgres_session_factory: sessionmaker[Session],
) -> None:
    started = Event()
    continue_lookup = Event()
    (
        service,
        principal,
        organization_id,
        target_id,
        challenge_value,
        user_id,
    ) = create_target(
        postgres_session_factory,
        PausedDNSVerifier(started, continue_lookup),
    )

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                service.verify_organization_target,
                principal,
                organization_id,
                target_id,
            )
            assert started.wait(timeout=5)
            rotated = service.rotate_challenge(principal, organization_id, target_id)
            continue_lookup.set()
            with pytest.raises(TargetVerificationFailed):
                future.result(timeout=15)

        assert rotated.challenge_value != challenge_value
        with postgres_session_factory() as session:
            target = session.get(SecurityTarget, target_id)
            challenge = session.scalar(
                select(TargetVerificationChallenge).where(
                    TargetVerificationChallenge.target_id == target_id
                )
            )
            assert target is not None
            assert target.verified_at is None
            assert challenge is not None
            assert challenge.challenge_hash != sha256(challenge_value.encode("ascii")).hexdigest()
    finally:
        continue_lookup.set()
        clean_target(postgres_session_factory, organization_id, user_id)
