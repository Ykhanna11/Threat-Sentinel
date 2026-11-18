from collections.abc import Callable
from uuid import UUID, uuid4

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.scans.models import SecurityScan
from threat_sentinel_api.modules.tenants.models import Organization


def create_organization(session: Session, creator: User) -> Organization:
    organization = Organization(
        name="Scan test organization",
        slug="scan-test-organization",
        created_by_user_id=creator.id,
    )
    session.add(organization)
    session.flush()
    return organization


def test_scan_accepts_personal_ownership(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    owner = make_user(subject="personal-owner")
    scan = SecurityScan(
        owner_user_id=owner.id,
        created_by_user_id=owner.id,
    )
    session.add(scan)
    session.flush()

    assert scan.owner_user_id == owner.id
    assert scan.organization_id is None
    assert scan.created_by_user_id == owner.id


def test_personal_scan_rejects_different_creator_and_owner(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    owner = make_user(subject="personal-owner")
    creator = make_user(subject="different-personal-creator")
    session.add(
        SecurityScan(
            owner_user_id=owner.id,
            created_by_user_id=creator.id,
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_scan_accepts_organization_ownership(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    creator = make_user(subject="organization-creator")
    organization = create_organization(session, creator)
    scan = SecurityScan(
        organization_id=organization.id,
        created_by_user_id=creator.id,
    )
    session.add(scan)
    session.flush()

    assert scan.owner_user_id is None
    assert scan.organization_id == organization.id
    assert scan.created_by_user_id == creator.id


def test_scan_rejects_missing_ownership_scope(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    creator = make_user(subject="missing-scope-creator")
    session.add(SecurityScan(created_by_user_id=creator.id))

    with pytest.raises(IntegrityError):
        session.flush()


def test_scan_rejects_both_ownership_scopes(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    creator = make_user(subject="both-scopes-creator")
    organization = create_organization(session, creator)
    session.add(
        SecurityScan(
            owner_user_id=creator.id,
            organization_id=organization.id,
            created_by_user_id=creator.id,
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_scan_requires_creator_reference(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    owner = make_user(subject="missing-creator-owner")
    session.add(SecurityScan(owner_user_id=owner.id))

    with pytest.raises(IntegrityError):
        session.flush()


@pytest.mark.parametrize(
    ("owner_user_id", "organization_id"),
    [
        pytest.param(uuid4(), None, id="unknown-owner-user"),
        pytest.param(None, uuid4(), id="unknown-organization"),
    ],
)
def test_scan_scope_foreign_keys_are_enforced(
    session: Session,
    make_user: Callable[..., User],
    owner_user_id: UUID | None,
    organization_id: UUID | None,
) -> None:
    creator = make_user(subject="scope-foreign-key-creator")
    session.add(
        SecurityScan(
            owner_user_id=owner_user_id,
            organization_id=organization_id,
            created_by_user_id=creator.id,
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_scan_creator_foreign_key_is_enforced(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    owner = make_user(subject="owner-with-unknown-creator")
    session.add(
        SecurityScan(
            owner_user_id=owner.id,
            created_by_user_id=uuid4(),
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_organization_deletion_cannot_cascade_scan_evidence(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    creator = make_user(subject="organization-deletion-creator")
    organization = create_organization(session, creator)
    session.add(
        SecurityScan(
            organization_id=organization.id,
            created_by_user_id=creator.id,
        )
    )
    session.flush()
    session.delete(organization)

    with pytest.raises(IntegrityError):
        session.flush()
