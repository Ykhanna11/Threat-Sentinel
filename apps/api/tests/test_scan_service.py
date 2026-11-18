from collections.abc import Callable
from uuid import uuid4

import pytest
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.identity.service import InvalidPrincipalError
from threat_sentinel_api.modules.scans.models import SecurityScan
from threat_sentinel_api.modules.scans.repository import ScanRepository
from threat_sentinel_api.modules.scans.service import ScanNotFound, ScanService
from threat_sentinel_api.modules.tenants.enums import (
    MembershipStatus,
    OrganizationRole,
    OrganizationStatus,
)
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.service import (
    OrganizationPermissionDenied,
    OrganizationScopeUnavailable,
    OrganizationService,
)

ISSUER = "https://identity.example"


class TrackingSession(Session):
    was_closed = False

    def close(self) -> None:
        self.was_closed = True
        super().close()


def tracking_session_factory(engine: Engine) -> tuple[Callable[[], Session], list[TrackingSession]]:
    sessions: list[TrackingSession] = []

    def create_session() -> TrackingSession:
        session = TrackingSession(bind=engine, expire_on_commit=False)
        sessions.append(session)
        return session

    return create_session, sessions


def make_principal(session: Session, user: User) -> AuthenticatedPrincipal:
    identity = session.scalar(select(ExternalIdentity).where(ExternalIdentity.user_id == user.id))
    assert identity is not None
    return AuthenticatedPrincipal(
        user_id=user.id,
        external_identity_id=identity.id,
        issuer=identity.issuer,
        subject=identity.subject,
        email=identity.email,
        email_verified=identity.email_verified_at is not None,
    )


def create_organization(session: Session, creator: User, slug: str) -> Organization:
    organization = Organization(
        name=f"Organization {slug}",
        slug=slug,
        created_by_user_id=creator.id,
    )
    session.add(organization)
    session.flush()
    return organization


def add_membership(
    session: Session,
    organization: Organization,
    user: User,
    role: OrganizationRole,
    status: MembershipStatus = MembershipStatus.ACTIVE,
) -> OrganizationMembership:
    membership = OrganizationMembership(
        organization=organization,
        user=user,
        role=role,
        status=status,
    )
    session.add(membership)
    session.flush()
    return membership


def add_personal_scan(session: Session, owner: User) -> SecurityScan:
    scan = SecurityScan(
        owner_user_id=owner.id,
        created_by_user_id=owner.id,
    )
    session.add(scan)
    session.flush()
    return scan


def add_organization_scan(
    session: Session,
    organization: Organization,
    creator: User,
) -> SecurityScan:
    scan = SecurityScan(
        organization_id=organization.id,
        created_by_user_id=creator.id,
    )
    session.add(scan)
    session.flush()
    return scan


def service_for(engine: Engine) -> ScanService:
    return ScanService(sessionmaker(bind=engine, expire_on_commit=False))


def test_personal_creation_uses_principal_and_needs_no_membership(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
) -> None:
    user = make_user(subject="personal-create")
    principal = make_principal(session, user)
    session.commit()

    scan = service_for(engine).create_personal_scan(principal)

    assert scan.owner_user_id == principal.user_id
    assert scan.created_by_user_id == principal.user_id
    assert scan.organization_id is None
    with Session(engine) as verify_session:
        persisted = verify_session.get(SecurityScan, scan.id)
        assert persisted is not None


def test_personal_listing_is_limited_to_principal_and_personal_scope(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
) -> None:
    owner = make_user(subject="personal-list-owner")
    other_user = make_user(subject="personal-list-other")
    organization = create_organization(session, owner, "personal-list-org")
    expected = {
        add_personal_scan(session, owner).id,
        add_personal_scan(session, owner).id,
    }
    add_personal_scan(session, other_user)
    add_organization_scan(session, organization, owner)
    principal = make_principal(session, owner)
    session.commit()

    scans = service_for(engine).list_personal_scans(principal)

    assert {scan.id for scan in scans} == expected


def test_personal_retrieval_is_owner_scoped(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
) -> None:
    owner = make_user(subject="personal-read-owner")
    other_user = make_user(subject="personal-read-other")
    scan = add_personal_scan(session, owner)
    owner_principal = make_principal(session, owner)
    other_principal = make_principal(session, other_user)
    session.commit()
    service = service_for(engine)

    assert service.get_personal_scan(owner_principal, scan.id).id == scan.id
    with pytest.raises(ScanNotFound) as other_owner:
        service.get_personal_scan(other_principal, scan.id)
    with pytest.raises(ScanNotFound) as missing:
        service.get_personal_scan(owner_principal, uuid4())

    assert type(other_owner.value) is type(missing.value)
    assert str(other_owner.value) == str(missing.value)


@pytest.mark.parametrize("operation", ["create", "list", "get"])
@pytest.mark.parametrize("user_status", [UserStatus.SUSPENDED, UserStatus.DEACTIVATED])
def test_personal_operations_recheck_local_user_status(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
    operation: str,
    user_status: UserStatus,
) -> None:
    user = make_user(subject=f"inactive-personal-{operation}-{user_status.value}")
    principal = make_principal(session, user)
    scan = add_personal_scan(session, user)
    user.status = user_status
    session.commit()
    service = service_for(engine)

    with pytest.raises(InvalidPrincipalError):
        if operation == "create":
            service.create_personal_scan(principal)
        elif operation == "list":
            service.list_personal_scans(principal)
        else:
            service.get_personal_scan(principal, scan.id)


def test_personal_operation_rejects_missing_local_identity_without_provisioning(
    engine: Engine,
) -> None:
    principal = AuthenticatedPrincipal(
        user_id=uuid4(),
        external_identity_id=uuid4(),
        issuer=ISSUER,
        subject="missing-local-identity",
    )

    with pytest.raises(InvalidPrincipalError):
        service_for(engine).create_personal_scan(principal)

    with Session(engine) as verify_session:
        assert verify_session.scalar(select(func.count()).select_from(User)) == 0
        assert verify_session.scalar(select(func.count()).select_from(ExternalIdentity)) == 0


@pytest.mark.parametrize(
    ("role", "allowed"),
    [
        (OrganizationRole.OWNER, True),
        (OrganizationRole.ADMIN, True),
        (OrganizationRole.MEMBER, True),
        (OrganizationRole.VIEWER, False),
    ],
)
def test_organization_creation_uses_local_role_and_principal_creator(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
    role: OrganizationRole,
    allowed: bool,
) -> None:
    user = make_user(subject=f"organization-create-{role.value}")
    principal = make_principal(session, user)
    organization = create_organization(session, user, f"create-{role.value}")
    add_membership(session, organization, user, role)
    session.commit()
    service = service_for(engine)

    if not allowed:
        with pytest.raises(OrganizationPermissionDenied):
            service.create_organization_scan(principal, organization.id)
        return

    scan = service.create_organization_scan(principal, organization.id)

    assert scan.organization_id == organization.id
    assert scan.created_by_user_id == principal.user_id
    assert scan.owner_user_id is None
    with Session(engine) as verify_session:
        assert (
            ScanRepository(verify_session).find_organization_by_id(scan.id, organization.id)
            is not None
        )


@pytest.mark.parametrize("role", list(OrganizationRole))
def test_all_local_roles_can_list_organization_scans(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
    role: OrganizationRole,
) -> None:
    user = make_user(subject=f"organization-list-{role.value}")
    principal = make_principal(session, user)
    organization = create_organization(session, user, f"list-{role.value}")
    other_organization = create_organization(session, user, f"other-list-{role.value}")
    add_membership(session, organization, user, role)
    expected = {
        add_organization_scan(session, organization, user).id,
        add_organization_scan(session, organization, user).id,
    }
    add_organization_scan(session, other_organization, user)
    add_personal_scan(session, user)
    session.commit()

    scans = service_for(engine).list_organization_scans(principal, organization.id)

    assert {scan.id for scan in scans} == expected


@pytest.mark.parametrize("role", list(OrganizationRole))
def test_all_local_roles_can_retrieve_organization_scans(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
    role: OrganizationRole,
) -> None:
    user = make_user(subject=f"organization-read-{role.value}")
    principal = make_principal(session, user)
    organization = create_organization(session, user, f"read-{role.value}")
    add_membership(session, organization, user, role)
    scan = add_organization_scan(session, organization, user)
    session.commit()

    result = service_for(engine).get_organization_scan(principal, organization.id, scan.id)

    assert result.id == scan.id


@pytest.mark.parametrize(
    "membership_status",
    [MembershipStatus.SUSPENDED, MembershipStatus.REMOVED],
)
def test_inactive_membership_denies_organization_operations(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
    membership_status: MembershipStatus,
) -> None:
    user = make_user(subject=f"inactive-membership-{membership_status.value}")
    principal = make_principal(session, user)
    organization = create_organization(session, user, f"inactive-{membership_status.value}")
    add_membership(session, organization, user, OrganizationRole.OWNER, membership_status)
    session.commit()

    with pytest.raises(OrganizationScopeUnavailable):
        service_for(engine).list_organization_scans(principal, organization.id)


@pytest.mark.parametrize(
    "organization_status",
    [OrganizationStatus.SUSPENDED, OrganizationStatus.ARCHIVED],
)
def test_inactive_organization_denies_organization_operations(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
    organization_status: OrganizationStatus,
) -> None:
    user = make_user(subject=f"inactive-organization-{organization_status.value}")
    principal = make_principal(session, user)
    organization = create_organization(session, user, f"org-{organization_status.value}")
    organization.status = organization_status
    add_membership(session, organization, user, OrganizationRole.OWNER)
    session.commit()

    with pytest.raises(OrganizationScopeUnavailable):
        service_for(engine).create_organization_scan(principal, organization.id)


@pytest.mark.parametrize("organization_exists", [True, False])
def test_inactive_local_user_denies_organization_operations(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
    organization_exists: bool,
) -> None:
    user = make_user(subject="inactive-organization-user")
    principal = make_principal(session, user)
    if organization_exists:
        organization = create_organization(session, user, "inactive-organization-user")
        add_membership(session, organization, user, OrganizationRole.OWNER)
        organization_id = organization.id
    else:
        organization_id = uuid4()
    user.status = UserStatus.SUSPENDED
    session.commit()

    with pytest.raises(InvalidPrincipalError):
        service_for(engine).list_organization_scans(principal, organization_id)


def test_nonmember_and_organization_creator_cannot_access_organization_scans(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
) -> None:
    creator = make_user(subject="organization-creator-not-member")
    principal = make_principal(session, creator)
    organization = create_organization(session, creator, "creator-not-member")
    add_organization_scan(session, organization, creator)
    session.commit()

    with pytest.raises(OrganizationScopeUnavailable):
        service_for(engine).list_organization_scans(principal, organization.id)


def test_cross_organization_and_missing_scans_raise_same_not_found(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
) -> None:
    user = make_user(subject="cross-organization-reader")
    principal = make_principal(session, user)
    authorized_organization = create_organization(session, user, "authorized-organization")
    other_organization = create_organization(session, user, "other-organization")
    add_membership(session, authorized_organization, user, OrganizationRole.MEMBER)
    other_scan = add_organization_scan(session, other_organization, user)
    session.commit()
    service = service_for(engine)

    with pytest.raises(ScanNotFound) as out_of_scope:
        service.get_organization_scan(principal, authorized_organization.id, other_scan.id)
    with pytest.raises(ScanNotFound) as missing:
        service.get_organization_scan(principal, authorized_organization.id, uuid4())

    assert type(out_of_scope.value) is type(missing.value)
    assert str(out_of_scope.value) == str(missing.value)


def test_missing_organization_is_scope_unavailable(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
) -> None:
    user = make_user(subject="missing-organization-scope")
    principal = make_principal(session, user)
    session.commit()

    with pytest.raises(OrganizationScopeUnavailable):
        service_for(engine).list_organization_scans(principal, uuid4())


def test_each_public_operation_uses_exactly_one_uow_session(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
) -> None:
    user = make_user(subject="one-uow-user")
    principal = make_principal(session, user)
    organization = create_organization(session, user, "one-uow-organization")
    add_membership(session, organization, user, OrganizationRole.OWNER)
    personal_scan = add_personal_scan(session, user)
    organization_scan = add_organization_scan(session, organization, user)
    session.commit()
    session_factory, sessions = tracking_session_factory(engine)
    service = ScanService(session_factory)
    operations: list[Callable[[], object]] = [
        lambda: service.create_personal_scan(principal),
        lambda: service.list_personal_scans(principal),
        lambda: service.get_personal_scan(principal, personal_scan.id),
        lambda: service.create_organization_scan(principal, organization.id),
        lambda: service.list_organization_scans(principal, organization.id),
        lambda: service.get_organization_scan(principal, organization.id, organization_scan.id),
    ]

    for operation in operations:
        count_before = len(sessions)
        operation()
        assert len(sessions) == count_before + 1
        assert sessions[-1].was_closed


def test_personal_repositories_share_the_operation_session(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = make_user(subject="personal-shared-session")
    principal = make_principal(session, user)
    session.commit()
    session_factory, sessions = tracking_session_factory(engine)
    identity_sessions: list[Session] = []
    scan_sessions: list[Session] = []
    original_identity_init = IdentityRepository.__init__
    original_scan_init = ScanRepository.__init__

    def track_identity_init(repository: IdentityRepository, db_session: Session) -> None:
        identity_sessions.append(db_session)
        original_identity_init(repository, db_session)

    def track_scan_init(repository: ScanRepository, db_session: Session) -> None:
        scan_sessions.append(db_session)
        original_scan_init(repository, db_session)

    monkeypatch.setattr(IdentityRepository, "__init__", track_identity_init)
    monkeypatch.setattr(ScanRepository, "__init__", track_scan_init)

    ScanService(session_factory).create_personal_scan(principal)

    assert len(sessions) == 1
    assert identity_sessions == [sessions[0]]
    assert scan_sessions == [sessions[0]]


def test_organization_services_and_repository_share_the_operation_session(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = make_user(subject="organization-shared-session")
    principal = make_principal(session, user)
    organization = create_organization(session, user, "organization-shared-session")
    add_membership(session, organization, user, OrganizationRole.OWNER)
    session.commit()
    session_factory, sessions = tracking_session_factory(engine)
    organization_sessions: list[Session] = []
    scan_sessions: list[Session] = []
    organization_service_repositories: list[OrganizationRepository] = []
    original_organization_repo_init = OrganizationRepository.__init__
    original_scan_repo_init = ScanRepository.__init__
    original_organization_service_init = OrganizationService.__init__

    def track_organization_repo_init(
        repository: OrganizationRepository,
        db_session: Session,
    ) -> None:
        organization_sessions.append(db_session)
        original_organization_repo_init(repository, db_session)

    def track_scan_repo_init(repository: ScanRepository, db_session: Session) -> None:
        scan_sessions.append(db_session)
        original_scan_repo_init(repository, db_session)

    def track_organization_service_init(
        service: OrganizationService,
        repository: OrganizationRepository,
    ) -> None:
        organization_service_repositories.append(repository)
        original_organization_service_init(service, repository)

    monkeypatch.setattr(OrganizationRepository, "__init__", track_organization_repo_init)
    monkeypatch.setattr(ScanRepository, "__init__", track_scan_repo_init)
    monkeypatch.setattr(OrganizationService, "__init__", track_organization_service_init)

    ScanService(session_factory).create_organization_scan(principal, organization.id)

    assert len(sessions) == 1
    assert organization_sessions == [sessions[0]]
    assert scan_sessions == [sessions[0]]
    assert organization_service_repositories[0]._session is sessions[0]


def test_failed_personal_creation_rolls_back_and_closes_session(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = make_user(subject="rollback-user")
    principal = make_principal(session, user)
    session.commit()
    session_factory, sessions = tracking_session_factory(engine)
    original_add = ScanRepository.add

    def add_then_fail(repository: ScanRepository, scan: SecurityScan) -> None:
        original_add(repository, scan)
        raise RuntimeError("scan persistence failed")

    monkeypatch.setattr(ScanRepository, "add", add_then_fail)

    with pytest.raises(RuntimeError, match="scan persistence failed"):
        ScanService(session_factory).create_personal_scan(principal)

    assert len(sessions) == 1
    assert sessions[0].was_closed
    with Session(engine) as verify_session:
        assert verify_session.scalar(select(func.count()).select_from(SecurityScan)) == 0


def test_creator_identity_does_not_grant_organization_access(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
) -> None:
    creator = make_user(subject="scan-creator")
    requester = make_user(subject="scan-requester")
    principal = make_principal(session, requester)
    organization = create_organization(session, creator, "creator-does-not-authorize")
    scan = add_organization_scan(session, organization, creator)
    session.commit()

    with pytest.raises(OrganizationScopeUnavailable):
        service_for(engine).get_organization_scan(
            principal,
            organization.id,
            scan.id,
        )


@pytest.mark.parametrize("mismatched_field", ["user_id", "external_identity_id"])
def test_organization_operations_reject_principal_identity_mismatch(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
    mismatched_field: str,
) -> None:
    user = make_user(subject=f"mismatched-organization-principal-{mismatched_field}")
    principal = make_principal(session, user)
    organization = create_organization(session, user, f"mismatch-{mismatched_field}")
    add_membership(session, organization, user, OrganizationRole.OWNER)
    session.commit()

    values = principal.model_dump()
    values[mismatched_field] = uuid4()
    mismatched_principal = AuthenticatedPrincipal(**values)

    with pytest.raises(InvalidPrincipalError):
        service_for(engine).list_organization_scans(
            mismatched_principal,
            organization.id,
        )
