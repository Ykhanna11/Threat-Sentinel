from collections.abc import Callable
from typing import cast
from uuid import UUID, uuid4

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from threat_sentinel_api.db.session import unit_of_work
from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.scans.models import SecurityScan
from threat_sentinel_api.modules.scans.repository import ScanRepository
from threat_sentinel_api.modules.tenants.models import Organization


def create_organization(
    session: Session,
    creator: User,
    *,
    name: str,
    slug: str,
) -> Organization:
    organization = Organization(
        name=name,
        slug=slug,
        created_by_user_id=creator.id,
    )
    session.add(organization)
    session.flush()
    return organization


def add_personal_scan(repository: ScanRepository, owner_user_id: UUID) -> SecurityScan:
    scan = SecurityScan(
        owner_user_id=owner_user_id,
        created_by_user_id=owner_user_id,
    )
    repository.add(scan)
    return scan


def add_organization_scan(
    repository: ScanRepository,
    organization_id: UUID,
    creator_user_id: UUID,
) -> SecurityScan:
    scan = SecurityScan(
        organization_id=organization_id,
        created_by_user_id=creator_user_id,
    )
    repository.add(scan)
    return scan


def test_personal_scan_can_be_retrieved_by_its_owner(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    owner = make_user(subject="personal-owner")
    repository = ScanRepository(session)
    scan = add_personal_scan(repository, owner.id)

    assert repository.find_personal_by_id(scan.id, owner.id) is scan


def test_personal_scan_is_not_retrieved_by_another_user(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    owner = make_user(subject="personal-owner")
    other_user = make_user(subject="other-user")
    repository = ScanRepository(session)
    scan = add_personal_scan(repository, owner.id)

    assert repository.find_personal_by_id(scan.id, other_user.id) is None


def test_personal_scan_list_is_limited_to_requested_owner(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    owner = make_user(subject="list-owner")
    other_user = make_user(subject="other-list-owner")
    repository = ScanRepository(session)
    expected = {
        add_personal_scan(repository, owner.id).id,
        add_personal_scan(repository, owner.id).id,
    }
    add_personal_scan(repository, other_user.id)
    organization = create_organization(
        session,
        owner,
        name="Personal list organization",
        slug="personal-list-organization",
    )
    add_organization_scan(repository, organization.id, owner.id)

    assert {scan.id for scan in repository.list_personal_for_owner(owner.id)} == expected


def test_organization_scan_can_be_retrieved_by_its_organization(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    creator = make_user(subject="organization-creator")
    organization = create_organization(
        session,
        creator,
        name="First organization",
        slug="first-organization",
    )
    repository = ScanRepository(session)
    scan = add_organization_scan(repository, organization.id, creator.id)

    assert repository.find_organization_by_id(scan.id, organization.id) is scan


def test_organization_scan_is_not_retrieved_by_another_organization(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    creator = make_user(subject="organization-creator")
    first = create_organization(
        session,
        creator,
        name="First organization",
        slug="first-organization",
    )
    second = create_organization(
        session,
        creator,
        name="Second organization",
        slug="second-organization",
    )
    repository = ScanRepository(session)
    scan = add_organization_scan(repository, first.id, creator.id)

    assert repository.find_organization_by_id(scan.id, second.id) is None


def test_organization_scan_list_is_limited_to_requested_organization(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    creator = make_user(subject="organization-creator")
    first = create_organization(
        session,
        creator,
        name="First organization",
        slug="first-organization",
    )
    second = create_organization(
        session,
        creator,
        name="Second organization",
        slug="second-organization",
    )
    repository = ScanRepository(session)
    expected = {
        add_organization_scan(repository, first.id, creator.id).id,
        add_organization_scan(repository, first.id, creator.id).id,
    }
    add_organization_scan(repository, second.id, creator.id)
    add_personal_scan(repository, creator.id)

    assert {scan.id for scan in repository.list_organization_for(first.id)} == expected


def test_personal_and_organization_lookups_cannot_cross_scopes(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    creator = make_user(subject="scope-creator")
    organization = create_organization(
        session,
        creator,
        name="Scoped organization",
        slug="scoped-organization",
    )
    repository = ScanRepository(session)
    personal_scan = add_personal_scan(repository, creator.id)
    organization_scan = add_organization_scan(repository, organization.id, creator.id)

    assert repository.find_personal_by_id(organization_scan.id, creator.id) is None
    assert repository.find_organization_by_id(personal_scan.id, organization.id) is None


def test_missing_scan_ids_return_no_result(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    user = make_user(subject="missing-scan-owner")
    organization = create_organization(
        session,
        user,
        name="Missing scan organization",
        slug="missing-scan-organization",
    )
    repository = ScanRepository(session)
    missing_scan_id = uuid4()

    assert repository.find_personal_by_id(missing_scan_id, user.id) is None
    assert repository.find_organization_by_id(missing_scan_id, organization.id) is None


def test_repository_rejects_missing_scope(session: Session) -> None:
    repository = ScanRepository(session)
    with pytest.raises(ValueError, match="owner_user_id is required"):
        repository.find_personal_by_id(uuid4(), cast(UUID, None))
    with pytest.raises(ValueError, match="owner_user_id is required"):
        repository.list_personal_for_owner(cast(UUID, None))
    with pytest.raises(ValueError, match="organization_id is required"):
        repository.find_organization_by_id(uuid4(), cast(UUID, None))
    with pytest.raises(ValueError, match="organization_id is required"):
        repository.list_organization_for(cast(UUID, None))


def test_repository_add_persists_with_the_caller_unit_of_work(
    engine: Engine,
    session: Session,
    make_user: Callable[..., User],
) -> None:
    owner = make_user(subject="uow-owner")
    session.commit()
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with unit_of_work(session_factory) as uow_session:
        repository = ScanRepository(uow_session)
        scan = add_personal_scan(repository, owner.id)
        scan_id = scan.id

    with Session(engine) as verify_session:
        assert ScanRepository(verify_session).find_personal_by_id(scan_id, owner.id) is not None
