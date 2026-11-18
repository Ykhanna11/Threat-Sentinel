from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from queue import Queue
from threading import Barrier, Event
from time import monotonic, sleep
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Connection, delete, event, func, or_, select, text
from sqlalchemy.orm import Session, sessionmaker

from threat_sentinel_api.db import authorization_locks
from threat_sentinel_api.db.authorization_locks import (
    lock_membership_for_no_key_update,
    lock_organization_for_no_key_update,
    lock_user_for_no_key_update,
)
from threat_sentinel_api.db.session import unit_of_work
from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import (
    AuthenticatedPrincipal,
    VerifiedAccessTokenClaims,
    VerifiedUserContext,
)
from threat_sentinel_api.modules.identity.service import IdentityService, InactiveUserError
from threat_sentinel_api.modules.scans.models import SecurityScan
from threat_sentinel_api.modules.scans.repository import ScanRepository
from threat_sentinel_api.modules.scans.service import ScanService
from threat_sentinel_api.modules.tenants.enums import (
    MembershipStatus,
    OrganizationRole,
    OrganizationStatus,
)
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.schemas import OrganizationCreate
from threat_sentinel_api.modules.tenants.service import (
    ActiveUserRequired,
    OrganizationAccessDenied,
    OrganizationService,
)

pytestmark = pytest.mark.postgres_integration

ISSUER = "https://authorization-locks.example"


@dataclass(frozen=True)
class IdentityFixture:
    user_id: UUID
    identity_id: UUID
    principal: AuthenticatedPrincipal
    context: VerifiedUserContext


class AuthorizationTestData:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self.factory = factory
        self.user_ids: set[UUID] = set()
        self.organization_ids: set[UUID] = set()

    def create_user(self) -> IdentityFixture:
        subject = str(uuid4())
        with self.factory() as session:
            user = User()
            identity = ExternalIdentity(
                user=user,
                issuer=ISSUER,
                subject=subject,
            )
            session.add(identity)
            session.flush()
            result = IdentityFixture(
                user_id=user.id,
                identity_id=identity.id,
                principal=AuthenticatedPrincipal(
                    user_id=user.id,
                    external_identity_id=identity.id,
                    issuer=ISSUER,
                    subject=subject,
                    email=None,
                    email_verified=False,
                ),
                context=VerifiedUserContext(issuer=ISSUER, subject=subject),
            )
            self.user_ids.add(user.id)
            session.commit()
        return result

    def create_organization(
        self,
        owner: IdentityFixture,
        *,
        membership_user: IdentityFixture | None = None,
        role: OrganizationRole = OrganizationRole.OWNER,
        membership_status: MembershipStatus = MembershipStatus.ACTIVE,
    ) -> UUID:
        with self.factory() as session:
            organization = Organization(
                name=f"Lock test {uuid4()}",
                slug=f"lock-test-{uuid4()}",
                created_by_user_id=owner.user_id,
            )
            session.add(organization)
            session.flush()
            session.add(
                OrganizationMembership(
                    organization_id=organization.id,
                    user_id=owner.user_id,
                    role=OrganizationRole.OWNER,
                    status=MembershipStatus.ACTIVE,
                )
            )
            if membership_user is not None and membership_user.user_id != owner.user_id:
                session.add(
                    OrganizationMembership(
                        organization_id=organization.id,
                        user_id=membership_user.user_id,
                        role=role,
                        status=membership_status,
                    )
                )
            organization_id = organization.id
            self.organization_ids.add(organization_id)
            session.commit()
        return organization_id

    def add_scan(self, creator: IdentityFixture, organization_id: UUID) -> UUID:
        with self.factory() as session:
            scan = SecurityScan(
                organization_id=organization_id,
                created_by_user_id=creator.user_id,
            )
            session.add(scan)
            session.flush()
            scan_id = scan.id
            session.commit()
        return scan_id

    def cleanup(self) -> None:
        with self.factory() as session:
            if self.user_ids:
                self.organization_ids.update(
                    session.scalars(
                        select(Organization.id).where(
                            Organization.created_by_user_id.in_(self.user_ids)
                        )
                    ).all()
                )
            if self.user_ids or self.organization_ids:
                scan_criteria = []
                if self.user_ids:
                    scan_criteria.extend(
                        (
                            SecurityScan.created_by_user_id.in_(self.user_ids),
                            SecurityScan.owner_user_id.in_(self.user_ids),
                        )
                    )
                if self.organization_ids:
                    scan_criteria.append(SecurityScan.organization_id.in_(self.organization_ids))
                session.execute(delete(SecurityScan).where(or_(*scan_criteria)))
                membership_criteria = []
                if self.user_ids:
                    membership_criteria.append(OrganizationMembership.user_id.in_(self.user_ids))
                if self.organization_ids:
                    membership_criteria.append(
                        OrganizationMembership.organization_id.in_(self.organization_ids)
                    )
                session.execute(delete(OrganizationMembership).where(or_(*membership_criteria)))
            if self.user_ids:
                session.execute(
                    delete(ExternalIdentity).where(ExternalIdentity.user_id.in_(self.user_ids))
                )
            if self.organization_ids:
                session.execute(
                    delete(Organization).where(Organization.id.in_(self.organization_ids))
                )
            if self.user_ids:
                session.execute(delete(User).where(User.id.in_(self.user_ids)))
            session.commit()


@pytest.fixture
def authorization_data(
    postgres_session_factory: sessionmaker[Session],
) -> AuthorizationTestData:
    data = AuthorizationTestData(postgres_session_factory)
    yield data
    data.cleanup()


def _claims(identity: IdentityFixture) -> VerifiedAccessTokenClaims:
    now = datetime.now(UTC)
    return VerifiedAccessTokenClaims(
        issuer=ISSUER,
        subject=identity.principal.subject,
        audiences=("threat-sentinel-api",),
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )


def _wait_for_reader(
    ready: Event,
    reader_pid: Queue[int],
) -> int:
    assert ready.wait(timeout=5), "authorization operation did not reach its synchronization point"
    return reader_pid.get(timeout=5)


def _pause_authorization(
    session: Session,
    ready: Event,
    release: Event,
    reader_pid: Queue[int],
) -> None:
    reader_pid.put(session.scalar(text("SELECT pg_backend_pid()")))
    ready.set()
    if not release.wait(timeout=10):
        raise TimeoutError("test did not release the paused authorization operation")


def _submit_writer(
    executor: ThreadPoolExecutor,
    factory: sessionmaker[Session],
    operation: Callable[[Session], None],
) -> tuple[Future[None], Event, Event, Queue[int], int]:
    waiting = Event()
    acquired = Event()
    writer_pid: Queue[int] = Queue()

    def run() -> None:
        with factory() as session, session.begin():
            pid = session.scalar(text("SELECT pg_backend_pid()"))
            writer_pid.put(pid)
            waiting.set()
            operation(session)
            acquired.set()

    future = executor.submit(run)
    assert waiting.wait(timeout=5), "writer did not start"
    return future, waiting, acquired, writer_pid, writer_pid.get(timeout=5)


def _assert_blocked_by(factory: sessionmaker[Session], waiting_pid: int, blocker_pid: int) -> None:
    deadline = monotonic() + 5
    with factory() as diagnostic:
        while monotonic() < deadline:
            blockers = diagnostic.scalars(
                text("SELECT unnest(pg_blocking_pids(:waiting_pid))"),
                {"waiting_pid": waiting_pid},
            ).all()
            if blocker_pid in blockers:
                return
            sleep(0.01)
    raise AssertionError(
        f"PostgreSQL did not report backend {blocker_pid} blocking backend {waiting_pid}"
    )


def _lock_user(session: Session, user_id: UUID) -> None:
    assert lock_user_for_no_key_update(session, user_id) is not None


def _membership_writer(
    user_id: UUID,
    organization_id: UUID,
    *,
    status: MembershipStatus | None = None,
    role: OrganizationRole | None = None,
) -> Callable[[Session], None]:
    def operation(session: Session) -> None:
        _lock_user(session, user_id)
        assert lock_organization_for_no_key_update(session, organization_id) is not None
        membership = lock_membership_for_no_key_update(session, user_id, organization_id)
        assert membership is not None
        if status is not None:
            membership.status = status
        if role is not None:
            membership.role = role
        session.flush()

    return operation


def _session_factory_with_postgres_timeouts(
    factory: sessionmaker[Session],
) -> sessionmaker[Session]:
    class BoundedPostgresSession(Session):
        pass

    def set_transaction_timeouts(
        _session: Session,
        _transaction: object,
        connection: Connection,
    ) -> None:
        connection.exec_driver_sql("SET LOCAL lock_timeout = '3s'")
        connection.exec_driver_sql("SET LOCAL statement_timeout = '10s'")

    event.listen(BoundedPostgresSession, "after_begin", set_transaction_timeouts)
    return sessionmaker(
        bind=factory.kw["bind"],
        class_=BoundedPostgresSession,
        expire_on_commit=False,
    )


def test_personal_scan_share_lock_blocks_user_writer(
    authorization_data: AuthorizationTestData,
    postgres_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = authorization_data.create_user()
    ready, release, reader_pid = Event(), Event(), Queue[int]()
    original_add = ScanRepository.add

    def pause_after_authorization(repository: ScanRepository, scan: SecurityScan) -> None:
        _pause_authorization(repository._session, ready, release, reader_pid)
        original_add(repository, scan)

    monkeypatch.setattr(ScanRepository, "add", pause_after_authorization)
    with ThreadPoolExecutor(max_workers=2) as executor:
        authorization = executor.submit(
            ScanService(postgres_session_factory).create_personal_scan,
            identity.principal,
        )
        try:
            blocker_pid = _wait_for_reader(ready, reader_pid)
            writer, _, acquired, _, writer_pid = _submit_writer(
                executor,
                postgres_session_factory,
                lambda session: _lock_user(session, identity.user_id),
            )
            _assert_blocked_by(postgres_session_factory, writer_pid, blocker_pid)
            assert not acquired.is_set()
        finally:
            release.set()
        authorization.result(timeout=10)
        writer.result(timeout=10)
        assert acquired.is_set()


def test_organization_scan_locks_rows_in_canonical_order(
    authorization_data: AuthorizationTestData,
    postgres_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = authorization_data.create_user()
    organization_id = authorization_data.create_organization(identity)
    ready, release, reader_pid = Event(), Event(), Queue[int]()
    lock_order: list[str] = []
    import threat_sentinel_api.modules.identity.repository as identity_repository_module
    import threat_sentinel_api.modules.tenants.repository as tenants_repository_module

    original_user_lock = identity_repository_module.lock_user_for_share
    original_org_lock = tenants_repository_module.lock_organization_for_share
    original_membership_lock = tenants_repository_module.lock_membership_for_share

    def track_user(session: Session, user_id: UUID) -> User | None:
        lock_order.append("user")
        return original_user_lock(session, user_id)

    def track_organization(session: Session, resource_id: UUID) -> Organization | None:
        lock_order.append("organization")
        return original_org_lock(session, resource_id)

    def track_membership(
        session: Session,
        user_id: UUID,
        resource_id: UUID,
    ) -> OrganizationMembership | None:
        lock_order.append("membership")
        return original_membership_lock(session, user_id, resource_id)

    original_add = ScanRepository.add

    def pause_after_authorization(repository: ScanRepository, scan: SecurityScan) -> None:
        _pause_authorization(repository._session, ready, release, reader_pid)
        original_add(repository, scan)

    monkeypatch.setattr(identity_repository_module, "lock_user_for_share", track_user)
    monkeypatch.setattr(
        tenants_repository_module,
        "lock_organization_for_share",
        track_organization,
    )
    monkeypatch.setattr(
        tenants_repository_module,
        "lock_membership_for_share",
        track_membership,
    )
    monkeypatch.setattr(ScanRepository, "add", pause_after_authorization)
    with ThreadPoolExecutor(max_workers=4) as executor:
        authorization = executor.submit(
            ScanService(postgres_session_factory).create_organization_scan,
            identity.principal,
            organization_id,
        )
        writers: list[tuple[Future[None], Event, int]] = []
        try:
            blocker_pid = _wait_for_reader(ready, reader_pid)
            lock_operations = (
                lambda session: _lock_user(session, identity.user_id),
                lambda session: lock_organization_for_no_key_update(session, organization_id),
                lambda session: lock_membership_for_no_key_update(
                    session,
                    identity.user_id,
                    organization_id,
                ),
            )
            for operation in lock_operations:
                future, _, acquired, _, waiting_pid = _submit_writer(
                    executor,
                    postgres_session_factory,
                    operation,
                )
                writers.append((future, acquired, waiting_pid))
                _assert_blocked_by(postgres_session_factory, waiting_pid, blocker_pid)
                assert not acquired.is_set()
            assert lock_order == ["user", "organization", "membership"]
        finally:
            release.set()
        authorization.result(timeout=10)
        for future, acquired, _ in writers:
            future.result(timeout=10)
            assert acquired.is_set()


def test_membership_writer_blocks_and_role_change_takes_effect_afterward(
    authorization_data: AuthorizationTestData,
    postgres_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = authorization_data.create_user()
    member = authorization_data.create_user()
    organization_id = authorization_data.create_organization(
        owner,
        membership_user=member,
        role=OrganizationRole.MEMBER,
    )
    ready, release, reader_pid = Event(), Event(), Queue[int]()
    original_add = ScanRepository.add

    def pause_after_authorization(repository: ScanRepository, scan: SecurityScan) -> None:
        _pause_authorization(repository._session, ready, release, reader_pid)
        original_add(repository, scan)

    monkeypatch.setattr(ScanRepository, "add", pause_after_authorization)
    with ThreadPoolExecutor(max_workers=2) as executor:
        authorization = executor.submit(
            ScanService(postgres_session_factory).create_organization_scan,
            member.principal,
            organization_id,
        )
        try:
            blocker_pid = _wait_for_reader(ready, reader_pid)
            writer, _, acquired, _, writer_pid = _submit_writer(
                executor,
                postgres_session_factory,
                _membership_writer(
                    member.user_id,
                    organization_id,
                    role=OrganizationRole.VIEWER,
                ),
            )
            _assert_blocked_by(postgres_session_factory, writer_pid, blocker_pid)
            assert not acquired.is_set()
        finally:
            release.set()
        authorization.result(timeout=10)
        writer.result(timeout=10)
    with pytest.raises(OrganizationAccessDenied):
        ScanService(postgres_session_factory).create_organization_scan(
            member.principal,
            organization_id,
        )


def test_missing_membership_locks_organization_and_serializes_creation(
    authorization_data: AuthorizationTestData,
    postgres_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = authorization_data.create_user()
    outsider = authorization_data.create_user()
    organization_id = authorization_data.create_organization(owner)
    ready, release, reader_pid = Event(), Event(), Queue[int]()
    original_find = OrganizationRepository.find_active_membership

    def pause_after_missing_membership(
        repository: OrganizationRepository,
        resource_id: UUID,
        issuer: str,
        subject: str,
    ) -> OrganizationMembership | None:
        membership = original_find(repository, resource_id, issuer, subject)
        assert membership is None
        _pause_authorization(repository._session, ready, release, reader_pid)
        return None

    monkeypatch.setattr(
        OrganizationRepository,
        "find_active_membership",
        pause_after_missing_membership,
    )
    with ThreadPoolExecutor(max_workers=3) as executor:
        authorization = executor.submit(
            ScanService(postgres_session_factory).create_organization_scan,
            outsider.principal,
            organization_id,
        )
        writers: list[tuple[Future[None], Event, int]] = []
        try:
            blocker_pid = _wait_for_reader(ready, reader_pid)
            organization_probe, _, acquired, _, waiting_pid = _submit_writer(
                executor,
                postgres_session_factory,
                lambda session: lock_organization_for_no_key_update(session, organization_id),
            )
            writers.append((organization_probe, acquired, waiting_pid))
            _assert_blocked_by(postgres_session_factory, waiting_pid, blocker_pid)

            def create_membership(session: Session) -> None:
                _lock_user(session, outsider.user_id)
                assert lock_organization_for_no_key_update(session, organization_id) is not None
                session.add(
                    OrganizationMembership(
                        organization_id=organization_id,
                        user_id=outsider.user_id,
                        role=OrganizationRole.MEMBER,
                        status=MembershipStatus.ACTIVE,
                    )
                )
                session.flush()

            creator, _, creator_acquired, _, creator_pid = _submit_writer(
                executor,
                postgres_session_factory,
                create_membership,
            )
            writers.append((creator, creator_acquired, creator_pid))
            _assert_blocked_by(postgres_session_factory, creator_pid, blocker_pid)
            assert not creator_acquired.is_set()
        finally:
            release.set()
        with pytest.raises(OrganizationAccessDenied):
            authorization.result(timeout=10)
        for future, acquired, _ in writers:
            future.result(timeout=10)
            assert acquired.is_set()
    with postgres_session_factory() as session:
        assert (
            session.scalar(
                select(OrganizationMembership.id).where(
                    OrganizationMembership.user_id == outsider.user_id,
                    OrganizationMembership.organization_id == organization_id,
                )
            )
            is not None
        )
    monkeypatch.setattr(OrganizationRepository, "find_active_membership", original_find)
    created_scan = ScanService(postgres_session_factory).create_organization_scan(
        outsider.principal,
        organization_id,
    )
    assert created_scan.organization_id == organization_id
    assert created_scan.created_by_user_id == outsider.user_id
    with postgres_session_factory() as session:
        membership = session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.user_id == outsider.user_id,
                OrganizationMembership.organization_id == organization_id,
            )
        )
        assert membership is not None
        assert membership.status is MembershipStatus.ACTIVE
        assert membership.role is OrganizationRole.MEMBER


def test_concurrent_organization_creation_shares_user_lock_without_deadlock(
    authorization_data: AuthorizationTestData,
    postgres_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    creator = authorization_data.create_user()
    both_user_locks_acquired = Barrier(2)
    backend_pids: Queue[int] = Queue()
    bounded_session_factory = _session_factory_with_postgres_timeouts(postgres_session_factory)
    import threat_sentinel_api.modules.identity.repository as identity_repository_module

    original_user_lock = identity_repository_module.lock_user_for_share

    def synchronize_after_user_lock(session: Session, user_id: UUID) -> User | None:
        user = original_user_lock(session, user_id)
        assert user is not None
        backend_pids.put(session.scalar(text("SELECT pg_backend_pid()")))
        both_user_locks_acquired.wait(timeout=5)
        return user

    monkeypatch.setattr(
        identity_repository_module,
        "lock_user_for_share",
        synchronize_after_user_lock,
    )

    def create_organization(name: str) -> Organization:
        with unit_of_work(bounded_session_factory) as session:
            return OrganizationService(OrganizationRepository(session)).create_organization(
                creator.context,
                OrganizationCreate(
                    name=name,
                    slug=f"concurrent-{name.lower().replace(' ', '-')}-{uuid4()}",
                ),
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        creations = [
            executor.submit(create_organization, "Concurrent One"),
            executor.submit(create_organization, "Concurrent Two"),
        ]
        organizations = [creation.result(timeout=15) for creation in creations]

    assert len(set(backend_pids.get(timeout=1) for _ in range(2))) == 2
    organization_ids = {organization.id for organization in organizations}
    assert len(organization_ids) == 2
    with postgres_session_factory() as session:
        persisted_organizations = set(
            session.scalars(
                select(Organization.id).where(Organization.id.in_(organization_ids))
            ).all()
        )
        assert persisted_organizations == organization_ids
        memberships = session.scalars(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id.in_(organization_ids)
            )
        ).all()
        assert len(memberships) == 2
        assert {
            membership.organization_id: (
                membership.user_id,
                membership.role,
                membership.status,
            )
            for membership in memberships
        } == {
            organization_id: (
                creator.user_id,
                OrganizationRole.OWNER,
                MembershipStatus.ACTIVE,
            )
            for organization_id in organization_ids
        }


def test_writer_first_membership_status_is_observed_by_authorization(
    authorization_data: AuthorizationTestData,
    postgres_session_factory: sessionmaker[Session],
) -> None:
    owner = authorization_data.create_user()
    member = authorization_data.create_user()
    organization_id = authorization_data.create_organization(
        owner,
        membership_user=member,
        role=OrganizationRole.MEMBER,
    )
    with postgres_session_factory() as session, session.begin():
        assert lock_user_for_no_key_update(session, member.user_id) is not None
        assert lock_organization_for_no_key_update(session, organization_id) is not None
        membership = lock_membership_for_no_key_update(
            session,
            member.user_id,
            organization_id,
        )
        assert membership is not None
        membership.status = MembershipStatus.SUSPENDED
    with pytest.raises(OrganizationAccessDenied):
        ScanService(postgres_session_factory).list_organization_scans(
            member.principal,
            organization_id,
        )

    user = authorization_data.create_user()
    with postgres_session_factory() as session, session.begin():
        assert lock_user_for_no_key_update(session, user.user_id) is not None
        row = session.get(User, user.user_id)
        assert row is not None
        row.status = UserStatus.SUSPENDED
    with pytest.raises(InactiveUserError):
        ScanService(postgres_session_factory).create_personal_scan(user.principal)

    active_owner = authorization_data.create_user()
    inactive_org_id = authorization_data.create_organization(active_owner)
    with postgres_session_factory() as session, session.begin():
        assert lock_user_for_no_key_update(session, active_owner.user_id) is not None
        assert lock_organization_for_no_key_update(session, inactive_org_id) is not None
        organization = session.get(Organization, inactive_org_id)
        assert organization is not None
        organization.status = OrganizationStatus.SUSPENDED
    with pytest.raises(OrganizationAccessDenied):
        ScanService(postgres_session_factory).list_organization_scans(
            active_owner.principal,
            inactive_org_id,
        )


def test_listing_locks_membership_set_until_materialization_finishes(
    authorization_data: AuthorizationTestData,
    postgres_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = authorization_data.create_user()
    member = authorization_data.create_user()
    existing_org_id = authorization_data.create_organization(
        owner,
        membership_user=member,
        role=OrganizationRole.MEMBER,
    )
    new_org_id = authorization_data.create_organization(owner)
    ready, release, reader_pid = Event(), Event(), Queue[int]()
    original_list = OrganizationRepository.list_active_for_identity

    def pause_after_materialization(
        repository: OrganizationRepository,
        issuer: str,
        subject: str,
    ) -> list[Organization]:
        organizations = original_list(repository, issuer, subject)
        _pause_authorization(repository._session, ready, release, reader_pid)
        return organizations

    monkeypatch.setattr(
        OrganizationRepository,
        "list_active_for_identity",
        pause_after_materialization,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:

        def list_in_uow() -> list[Organization]:
            with unit_of_work(postgres_session_factory) as session:
                return OrganizationService(OrganizationRepository(session)).list_organizations(
                    member.context
                )

        listing = executor.submit(list_in_uow)
        try:
            blocker_pid = _wait_for_reader(ready, reader_pid)

            def create_membership(session: Session) -> None:
                _lock_user(session, member.user_id)
                assert lock_organization_for_no_key_update(session, new_org_id) is not None
                session.add(
                    OrganizationMembership(
                        organization_id=new_org_id,
                        user_id=member.user_id,
                        role=OrganizationRole.VIEWER,
                    )
                )
                session.flush()

            writer, _, acquired, _, writer_pid = _submit_writer(
                executor,
                postgres_session_factory,
                create_membership,
            )
            _assert_blocked_by(postgres_session_factory, writer_pid, blocker_pid)
            assert not acquired.is_set()
        finally:
            release.set()
        listed = listing.result(timeout=10)
        writer.result(timeout=10)
        assert acquired.is_set()
    assert [organization.id for organization in listed] == [existing_org_id]
    with postgres_session_factory() as session, session.begin():
        listed_after = OrganizationService(OrganizationRepository(session)).list_organizations(
            member.context
        )
        assert {organization.id for organization in listed_after} == {
            existing_org_id,
            new_org_id,
        }


def test_organization_listing_locks_same_type_rows_in_uuid_order(
    authorization_data: AuthorizationTestData,
    postgres_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import threat_sentinel_api.modules.identity.repository as identity_repository_module
    import threat_sentinel_api.modules.tenants.repository as tenants_repository_module

    owner = authorization_data.create_user()
    member = authorization_data.create_user()
    organization_ids = {
        authorization_data.create_organization(
            owner,
            membership_user=member,
            role=OrganizationRole.MEMBER,
        )
        for _ in range(3)
    }
    with postgres_session_factory() as session:
        membership_ids = set(
            session.scalars(
                select(OrganizationMembership.id).where(
                    OrganizationMembership.user_id == member.user_id
                )
            ).all()
        )

    lock_order: list[tuple[str, UUID]] = []
    original_user_lock = identity_repository_module.lock_user_for_share
    original_organization_lock = authorization_locks.lock_organization_for_share
    original_membership_lock = tenants_repository_module.lock_membership_by_id_for_share

    def track_user(session: Session, user_id: UUID) -> User | None:
        lock_order.append(("user", user_id))
        return original_user_lock(session, user_id)

    def track_organization(session: Session, organization_id: UUID) -> Organization | None:
        lock_order.append(("organization", organization_id))
        return original_organization_lock(session, organization_id)

    def track_membership(
        session: Session,
        membership_id: UUID,
        user_id: UUID,
    ) -> OrganizationMembership | None:
        lock_order.append(("membership", membership_id))
        return original_membership_lock(session, membership_id, user_id)

    monkeypatch.setattr(identity_repository_module, "lock_user_for_share", track_user)
    monkeypatch.setattr(
        authorization_locks,
        "lock_organization_for_share",
        track_organization,
    )
    monkeypatch.setattr(
        tenants_repository_module,
        "lock_membership_by_id_for_share",
        track_membership,
    )
    with unit_of_work(postgres_session_factory) as session:
        organizations = OrganizationService(OrganizationRepository(session)).list_organizations(
            member.context
        )

    assert {organization.id for organization in organizations} == organization_ids
    assert lock_order == [
        ("user", member.user_id),
        *(("organization", organization_id) for organization_id in sorted(organization_ids)),
        *(("membership", membership_id) for membership_id in sorted(membership_ids)),
    ]


def test_principal_resolution_refreshes_stale_user_state_before_issuance(
    authorization_data: AuthorizationTestData,
    postgres_session_factory: sessionmaker[Session],
) -> None:
    identity = authorization_data.create_user()
    with postgres_session_factory() as stale_session:
        cached_user = stale_session.get(User, identity.user_id)
        assert cached_user is not None and cached_user.status is UserStatus.ACTIVE
        with postgres_session_factory() as writer, writer.begin():
            assert lock_user_for_no_key_update(writer, identity.user_id) is not None
            changed_user = writer.get(User, identity.user_id)
            assert changed_user is not None
            changed_user.status = UserStatus.SUSPENDED

        with pytest.raises(InactiveUserError):
            IdentityService(IdentityRepository(stale_session)).resolve_authenticated_principal(
                _claims(identity)
            )


def test_organization_creation_serializes_with_user_status_writer(
    authorization_data: AuthorizationTestData,
    postgres_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    creator = authorization_data.create_user()
    ready, release, reader_pid = Event(), Event(), Queue[int]()
    original_create = OrganizationRepository.create_with_owner

    def pause_before_insert(
        repository: OrganizationRepository,
        details: OrganizationCreate,
        owner: User,
    ) -> Organization:
        _pause_authorization(repository._session, ready, release, reader_pid)
        return original_create(repository, details, owner)

    monkeypatch.setattr(OrganizationRepository, "create_with_owner", pause_before_insert)
    with ThreadPoolExecutor(max_workers=2) as executor:

        def create() -> Organization:
            with unit_of_work(postgres_session_factory) as session:
                return OrganizationService(OrganizationRepository(session)).create_organization(
                    creator.context,
                    OrganizationCreate(name="Lock ordered", slug=f"lock-ordered-{uuid4()}"),
                )

        creation = executor.submit(create)
        try:
            blocker_pid = _wait_for_reader(ready, reader_pid)

            def suspend_user(session: Session) -> None:
                assert lock_user_for_no_key_update(session, creator.user_id) is not None
                user = session.get(User, creator.user_id)
                assert user is not None
                user.status = UserStatus.SUSPENDED

            writer, _, acquired, _, writer_pid = _submit_writer(
                executor,
                postgres_session_factory,
                suspend_user,
            )
            _assert_blocked_by(postgres_session_factory, writer_pid, blocker_pid)
            assert not acquired.is_set()
        finally:
            release.set()
        created = creation.result(timeout=10)
        writer.result(timeout=10)
        assert acquired.is_set()
    authorization_data.organization_ids.add(created.id)
    with postgres_session_factory() as session:
        membership = session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == created.id,
                OrganizationMembership.user_id == creator.user_id,
            )
        )
        assert membership is not None and membership.role is OrganizationRole.OWNER

    inactive_creator = authorization_data.create_user()
    with postgres_session_factory() as session, session.begin():
        assert lock_user_for_no_key_update(session, inactive_creator.user_id) is not None
        inactive_user = session.get(User, inactive_creator.user_id)
        assert inactive_user is not None
        inactive_user.status = UserStatus.SUSPENDED
    with pytest.raises(ActiveUserRequired):
        with unit_of_work(postgres_session_factory) as session:
            OrganizationService(OrganizationRepository(session)).create_organization(
                inactive_creator.context,
                OrganizationCreate(name="Must not exist", slug=f"inactive-{uuid4()}"),
            )


def test_failed_scan_transaction_rolls_back_and_releases_user_lock(
    authorization_data: AuthorizationTestData,
    postgres_session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = authorization_data.create_user()
    sessions: list[Session] = []

    class TrackingSession(Session):
        def close(self) -> None:
            super().close()
            sessions.append(self)

    def session_factory() -> Session:
        return TrackingSession(
            bind=postgres_session_factory.kw["bind"],
            expire_on_commit=False,
        )

    original_add = ScanRepository.add

    def add_then_fail(repository: ScanRepository, scan: SecurityScan) -> None:
        original_add(repository, scan)
        raise RuntimeError("intentional PostgreSQL rollback test")

    monkeypatch.setattr(ScanRepository, "add", add_then_fail)
    with pytest.raises(RuntimeError, match="intentional PostgreSQL rollback test"):
        ScanService(session_factory).create_personal_scan(identity.principal)

    assert len(sessions) == 1
    assert not sessions[0].in_transaction()
    with postgres_session_factory() as session, session.begin():
        assert (
            session.scalar(
                select(func.count())
                .select_from(SecurityScan)
                .where(SecurityScan.owner_user_id == identity.user_id)
            )
            == 0
        )
        assert lock_user_for_no_key_update(session, identity.user_id) is not None
