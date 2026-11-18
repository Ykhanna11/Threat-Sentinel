from collections.abc import Iterable
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership


def lock_user_for_share(session: Session, user_id: UUID) -> User | None:
    """Lock and refresh one User row for an authorization read."""
    statement = (
        select(User)
        .where(User.id == user_id)
        .with_for_update(read=True, of=User)
        .execution_options(populate_existing=True)
    )
    return session.scalar(statement)


def lock_user_for_no_key_update(session: Session, user_id: UUID) -> User | None:
    """Lock and refresh one User row before changing authorization state."""
    statement = (
        select(User)
        .where(User.id == user_id)
        .with_for_update(key_share=True, of=User)
        .execution_options(populate_existing=True)
    )
    return session.scalar(statement)


def lock_organization_for_share(session: Session, organization_id: UUID) -> Organization | None:
    """Lock and refresh one Organization row for an authorization read."""
    statement = (
        select(Organization)
        .where(Organization.id == organization_id)
        .with_for_update(read=True, of=Organization)
        .execution_options(populate_existing=True)
    )
    return session.scalar(statement)


def lock_organization_for_no_key_update(
    session: Session,
    organization_id: UUID,
) -> Organization | None:
    """Lock and refresh one Organization row before changing authorization state."""
    statement = (
        select(Organization)
        .where(Organization.id == organization_id)
        .with_for_update(key_share=True, of=Organization)
        .execution_options(populate_existing=True)
    )
    return session.scalar(statement)


def lock_membership_for_share(
    session: Session,
    user_id: UUID,
    organization_id: UUID,
) -> OrganizationMembership | None:
    """Lock one membership, including inactive rows, for an authorization read."""
    statement = (
        select(OrganizationMembership)
        .where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == organization_id,
        )
        .with_for_update(read=True, of=OrganizationMembership)
        .execution_options(populate_existing=True)
    )
    return session.scalar(statement)


def lock_membership_for_no_key_update(
    session: Session,
    user_id: UUID,
    organization_id: UUID,
) -> OrganizationMembership | None:
    """Lock one membership before changing its authorization state."""
    statement = (
        select(OrganizationMembership)
        .where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == organization_id,
        )
        .with_for_update(key_share=True, of=OrganizationMembership)
        .execution_options(populate_existing=True)
    )
    return session.scalar(statement)


def lock_organizations_for_share(
    session: Session,
    organization_ids: Iterable[UUID],
) -> list[Organization]:
    """Lock existing organizations one at a time in UUID order."""
    organizations: list[Organization] = []
    for organization_id in sorted(set(organization_ids)):
        organization = lock_organization_for_share(session, organization_id)
        if organization is not None:
            organizations.append(organization)
    return organizations


def lock_membership_by_id_for_share(
    session: Session,
    membership_id: UUID,
    user_id: UUID,
) -> OrganizationMembership | None:
    """Lock one identified membership for an authorization read."""
    statement = (
        select(OrganizationMembership)
        .where(
            OrganizationMembership.id == membership_id,
            OrganizationMembership.user_id == user_id,
        )
        .with_for_update(read=True, of=OrganizationMembership)
        .execution_options(populate_existing=True)
    )
    return session.scalar(statement)
