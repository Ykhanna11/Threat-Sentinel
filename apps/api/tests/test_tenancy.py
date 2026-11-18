from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, StatementError
from sqlalchemy.orm import Session

from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.schemas import VerifiedUserContext
from threat_sentinel_api.modules.tenants.enums import (
    InvitationStatus,
    MembershipStatus,
    OrganizationRole,
)
from threat_sentinel_api.modules.tenants.models import (
    OrganizationInvitation,
    OrganizationMembership,
)
from threat_sentinel_api.modules.tenants.invariants import (
    ActiveOwnerRetentionError,
    require_active_owner,
)
from threat_sentinel_api.modules.tenants.schemas import OrganizationCreate
from threat_sentinel_api.modules.tenants.service import (
    ActiveUserRequired,
    OrganizationAccessDenied,
    OrganizationConflict,
    OrganizationService,
)


def identity_context(subject: str) -> VerifiedUserContext:
    return VerifiedUserContext(
        issuer="https://identity.example",
        subject=subject,
    )


def _identity_id(session: Session, user: User) -> UUID:
    identity_id = session.scalar(
        select(ExternalIdentity.id).where(ExternalIdentity.user_id == user.id)
    )
    assert identity_id is not None
    return identity_id


def test_user_can_have_memberships_in_multiple_organizations(
    session: Session,
    make_user: Callable[..., User],
    organization_service: OrganizationService,
) -> None:
    make_user(subject="owner")
    member = make_user(subject="member")
    owner_context = identity_context("owner")
    member_context = identity_context("member")
    first = organization_service.create_organization(
        owner_context,
        OrganizationCreate(name="First organization", slug="first"),
    )
    second = organization_service.create_organization(
        owner_context,
        OrganizationCreate(name="Second organization", slug="second"),
    )
    session.add_all(
        [
            OrganizationMembership(
                organization=first,
                user=member,
                role=OrganizationRole.VIEWER,
            ),
            OrganizationMembership(
                organization=second,
                user=member,
                role=OrganizationRole.MEMBER,
            ),
        ]
    )
    session.flush()

    memberships = session.scalars(
        select(OrganizationMembership).where(OrganizationMembership.user_id == member.id)
    ).all()

    assert len(memberships) == 2
    assert {membership.role for membership in memberships} == {
        OrganizationRole.VIEWER,
        OrganizationRole.MEMBER,
    }
    assert {
        organization.id for organization in organization_service.list_organizations(member_context)
    } == {
        first.id,
        second.id,
    }
    assert organization_service.require_active_membership(owner_context, first.id).role is (
        OrganizationRole.OWNER
    )


def test_organization_creation_requires_active_user_and_assigns_explicit_owner(
    make_user: Callable[..., User],
    organization_service: OrganizationService,
) -> None:
    user = make_user(subject="creator")
    organization = organization_service.create_organization(
        identity_context("creator"),
        OrganizationCreate(name="  Acme  ", slug="acme"),
    )

    assert organization.name == "Acme"
    assert organization.created_by_user_id == user.id
    assert organization_service.require_active_membership(
        identity_context("creator"),
        organization.id,
    ).role is (OrganizationRole.OWNER)

    with pytest.raises(ActiveUserRequired):
        organization_service.create_organization(
            identity_context("unknown"),
            OrganizationCreate(name="Orphan", slug="orphan"),
        )


def test_projected_membership_state_must_retain_an_active_owner() -> None:
    owner = OrganizationMembership(
        role=OrganizationRole.OWNER,
        status=MembershipStatus.ACTIVE,
    )
    viewer = OrganizationMembership(
        role=OrganizationRole.VIEWER,
        status=MembershipStatus.ACTIVE,
    )

    require_active_owner([owner, viewer])

    owner.status = MembershipStatus.SUSPENDED
    with pytest.raises(ActiveOwnerRetentionError):
        require_active_owner([owner, viewer])


def test_organization_slug_is_unique(
    make_user: Callable[..., User],
    organization_service: OrganizationService,
) -> None:
    make_user(subject="creator")
    organization_service.create_organization(
        identity_context("creator"),
        OrganizationCreate(name="One", slug="same-slug"),
    )

    with pytest.raises(OrganizationConflict):
        organization_service.create_organization(
            identity_context("creator"),
            OrganizationCreate(name="Two", slug="same-slug"),
        )


def test_organization_access_requires_active_database_membership(
    session: Session,
    make_user: Callable[..., User],
    organization_service: OrganizationService,
) -> None:
    make_user(subject="owner")
    outsider = make_user(subject="outsider")
    owner_context = identity_context("owner")
    outsider_context = identity_context("outsider")
    organization = organization_service.create_organization(
        owner_context,
        OrganizationCreate(name="Private", slug="private"),
    )

    with pytest.raises(OrganizationAccessDenied):
        organization_service.require_active_membership(outsider_context, organization.id)

    membership = OrganizationMembership(
        organization=organization,
        user=outsider,
        role=OrganizationRole.VIEWER,
        status=MembershipStatus.SUSPENDED,
    )
    session.add(membership)
    session.flush()

    with pytest.raises(OrganizationAccessDenied):
        organization_service.require_active_membership(outsider_context, organization.id)

    membership.status = MembershipStatus.ACTIVE
    session.flush()
    assert (
        organization_service.require_active_membership(outsider_context, organization.id)
        is membership
    )


def test_duplicate_user_membership_in_one_organization_is_rejected(
    session: Session,
    make_user: Callable[..., User],
    organization_service: OrganizationService,
) -> None:
    make_user(subject="owner")
    member = make_user(subject="member")
    organization = organization_service.create_organization(
        identity_context("owner"),
        OrganizationCreate(name="Unique membership", slug="unique-membership"),
    )
    session.add(
        OrganizationMembership(
            organization=organization,
            user=member,
            role=OrganizationRole.MEMBER,
        )
    )
    session.flush()
    session.add(
        OrganizationMembership(
            organization=organization,
            user=member,
            role=OrganizationRole.ADMIN,
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_role_vocabulary_is_enforced_by_database_type(
    session: Session,
    make_user: Callable[..., User],
    organization_service: OrganizationService,
) -> None:
    make_user(subject="owner")
    member = make_user(subject="member")
    organization = organization_service.create_organization(
        identity_context("owner"),
        OrganizationCreate(name="Roles", slug="roles"),
    )
    session.add(
        OrganizationMembership(
            organization=organization,
            user=member,
            role="superuser",
        )
    )

    with pytest.raises(StatementError):
        session.flush()


def test_invitation_states_expiration_and_accepted_membership_integrity(
    session: Session,
    make_user: Callable[..., User],
    organization_service: OrganizationService,
) -> None:
    inviter = make_user(subject="inviter")
    invitee = make_user(subject="invitee")
    organization = organization_service.create_organization(
        identity_context("inviter"),
        OrganizationCreate(name="Invitations", slug="invitations"),
    )
    accepted_membership = OrganizationMembership(
        organization=organization,
        user=invitee,
        role=OrganizationRole.MEMBER,
    )
    session.add(accepted_membership)
    session.flush()
    now = datetime.now(UTC)
    inviter_identity_id = _identity_id(session, inviter)
    session.add_all(
        [
            OrganizationInvitation(
                organization=organization,
                inviter=inviter,
                intended_email="pending@example.test",
                intended_identity_id=inviter_identity_id,
                token_hash="a" * 64,
                status=InvitationStatus.PENDING,
                expires_at=now + timedelta(days=2),
            ),
            OrganizationInvitation(
                organization=organization,
                inviter=inviter,
                intended_email="revoked@example.test",
                status=InvitationStatus.REVOKED,
                revoked_at=now,
                expires_at=now + timedelta(days=2),
            ),
            OrganizationInvitation(
                organization=organization,
                inviter=inviter,
                intended_email="expired@example.test",
                status=InvitationStatus.EXPIRED,
                created_at=now - timedelta(days=3),
                expires_at=now - timedelta(days=2),
            ),
            OrganizationInvitation(
                organization=organization,
                inviter=inviter,
                intended_email="accepted@example.test",
                status=InvitationStatus.ACCEPTED,
                accepted_at=now,
                accepted_membership_id=accepted_membership.id,
                expires_at=now + timedelta(days=2),
            ),
        ]
    )
    session.flush()

    invitations = session.scalars(
        select(OrganizationInvitation).order_by(OrganizationInvitation.intended_email)
    ).all()

    assert {invitation.status for invitation in invitations} == set(InvitationStatus)
    assert all(invitation.organization_id == organization.id for invitation in invitations)
    accepted = next(
        invitation for invitation in invitations if invitation.status is InvitationStatus.ACCEPTED
    )
    assert accepted.inviter_user_id == inviter.id
    assert accepted.accepted_membership is not None
    assert accepted.accepted_membership.user_id == invitee.id


def test_duplicate_pending_invitation_email_is_normalized_per_organization(
    session: Session,
    make_user: Callable[..., User],
    organization_service: OrganizationService,
) -> None:
    inviter = make_user(subject="inviter")
    organization = organization_service.create_organization(
        identity_context("inviter"),
        OrganizationCreate(name="Pending invites", slug="pending-invites"),
    )
    expires_at = datetime.now(UTC) + timedelta(days=1)
    session.add(
        OrganizationInvitation(
            organization=organization,
            inviter=inviter,
            intended_email="  Person@Example.Test ",
            intended_identity_id=_identity_id(session, inviter),
            token_hash="a" * 64,
            expires_at=expires_at,
        )
    )
    session.flush()
    session.add(
        OrganizationInvitation(
            organization=organization,
            inviter=inviter,
            intended_email="person@example.test",
            intended_identity_id=_identity_id(session, inviter),
            token_hash="b" * 64,
            expires_at=expires_at,
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_revoked_invitation_can_be_reissued_and_email_can_be_invited_elsewhere(
    session: Session,
    make_user: Callable[..., User],
    organization_service: OrganizationService,
) -> None:
    inviter = make_user(subject="inviter")
    first = organization_service.create_organization(
        identity_context("inviter"),
        OrganizationCreate(name="First invite org", slug="first-invite-org"),
    )
    second = organization_service.create_organization(
        identity_context("inviter"),
        OrganizationCreate(name="Second invite org", slug="second-invite-org"),
    )
    now = datetime.now(UTC)
    email = "person@example.test"
    inviter_identity_id = _identity_id(session, inviter)
    session.add_all(
        [
            OrganizationInvitation(
                organization=first,
                inviter=inviter,
                intended_email=email,
                intended_identity_id=inviter_identity_id,
                status=InvitationStatus.REVOKED,
                revoked_at=now,
                expires_at=now + timedelta(days=1),
            ),
            OrganizationInvitation(
                organization=first,
                inviter=inviter,
                intended_email=email,
                intended_identity_id=inviter_identity_id,
                token_hash="a" * 64,
                expires_at=now + timedelta(days=1),
            ),
            OrganizationInvitation(
                organization=second,
                inviter=inviter,
                intended_email=email,
                intended_identity_id=inviter_identity_id,
                token_hash="b" * 64,
                expires_at=now + timedelta(days=1),
            ),
        ]
    )

    session.flush()

    assert (
        session.scalar(
            select(OrganizationInvitation.id).where(
                OrganizationInvitation.organization_id == first.id,
                OrganizationInvitation.status == InvitationStatus.PENDING,
            )
        )
        is not None
    )


def test_invitation_cannot_accept_membership_from_another_organization(
    session: Session,
    make_user: Callable[..., User],
    organization_service: OrganizationService,
) -> None:
    inviter = make_user(subject="inviter")
    invitee = make_user(subject="invitee")
    first = organization_service.create_organization(
        identity_context("inviter"),
        OrganizationCreate(name="First", slug="first-org"),
    )
    second = organization_service.create_organization(
        identity_context("inviter"),
        OrganizationCreate(name="Second", slug="second-org"),
    )
    membership = OrganizationMembership(
        organization=second,
        user=invitee,
        role=OrganizationRole.MEMBER,
    )
    session.add(membership)
    session.flush()
    session.add(
        OrganizationInvitation(
            organization=first,
            inviter=inviter,
            intended_email="invitee@example.test",
            status=InvitationStatus.ACCEPTED,
            accepted_at=datetime.now(UTC),
            accepted_membership_id=membership.id,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_accepted_invitation_requires_accepted_membership_and_timestamp(
    session: Session,
    make_user: Callable[..., User],
    organization_service: OrganizationService,
) -> None:
    inviter = make_user(subject="inviter")
    organization = organization_service.create_organization(
        identity_context("inviter"),
        OrganizationCreate(name="Acceptance", slug="acceptance"),
    )
    session.add(
        OrganizationInvitation(
            organization=organization,
            inviter=inviter,
            intended_email="pending@example.test",
            status=InvitationStatus.ACCEPTED,
            expires_at=datetime.now(UTC) + timedelta(days=1),
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()
