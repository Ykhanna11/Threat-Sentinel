from base64 import urlsafe_b64decode
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from threat_sentinel_api.modules.audit.models import SecurityAuditEvent
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.targets.hostname import HostnameCanonicalizationError
from threat_sentinel_api.modules.targets.models import (
    SecurityTarget,
    TargetVerificationChallenge,
)
from threat_sentinel_api.modules.targets.service import (
    TargetConflict,
    TargetService,
)
from threat_sentinel_api.modules.tenants.authorization import (
    OrganizationScanAction,
    OrganizationTargetAction,
    allows_organization_scan_action,
    allows_organization_target_action,
)
from threat_sentinel_api.modules.tenants.enums import (
    MembershipStatus,
    OrganizationRole,
)
from threat_sentinel_api.modules.tenants.models import Organization, OrganizationMembership
from threat_sentinel_api.modules.tenants.service import (
    OrganizationPermissionDenied,
    OrganizationScopeUnavailable,
)
from threat_sentinel_api.modules.targets.repository import TargetRepository

ISSUER = "https://target-tests.example"


def create_organization_principal(
    session: Session,
    make_user: Callable[..., User],
    *,
    role: OrganizationRole = OrganizationRole.OWNER,
) -> tuple[Organization, AuthenticatedPrincipal, User]:
    subject = f"target-user-{uuid4()}"
    user = make_user(issuer=ISSUER, subject=subject)
    identity_id = session.scalar(
        select(ExternalIdentity.id).where(ExternalIdentity.user_id == user.id)
    )
    assert identity_id is not None
    principal = AuthenticatedPrincipal(
        user_id=user.id,
        external_identity_id=identity_id,
        issuer=ISSUER,
        subject=subject,
    )
    organization = Organization(
        name=f"Target organization {uuid4()}",
        slug=f"target-{uuid4()}",
        created_by_user_id=user.id,
    )
    session.add(organization)
    session.flush()
    session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=user.id,
            role=role,
            status=MembershipStatus.ACTIVE,
        )
    )
    session.flush()
    return organization, principal, user


def target_service(session: Session) -> TargetService:
    return TargetService(sessionmaker(bind=session.get_bind(), expire_on_commit=False))


def get_challenge(
    session: Session,
    target_id: UUID,
) -> TargetVerificationChallenge:
    challenge = session.scalar(
        select(TargetVerificationChallenge).where(
            TargetVerificationChallenge.target_id == target_id
        )
    )
    assert challenge is not None
    return challenge


@pytest.mark.parametrize(
    "role",
    [OrganizationRole.OWNER, OrganizationRole.ADMIN],
    ids=["owner", "admin"],
)
def test_target_creation_canonicalizes_and_stores_only_challenge_hash(
    session: Session,
    make_user: Callable[..., User],
    role: OrganizationRole,
) -> None:
    organization, principal, _ = create_organization_principal(
        session,
        make_user,
        role=role,
    )
    session.commit()

    issued = target_service(session).create_organization_target(
        principal,
        organization.id,
        "BÜCHER.example.",
    )

    assert issued.hostname == "xn--bcher-kva.example"
    assert len(urlsafe_b64decode(issued.challenge_value + "==")) == 32
    assert issued.challenge_value not in repr(issued)
    with Session(session.get_bind()) as verification_session:
        target = verification_session.get(SecurityTarget, issued.target_id)
        assert target is not None
        assert target.verified_at is None
        challenge = get_challenge(verification_session, issued.target_id)
        assert (
            challenge.challenge_hash == sha256(issued.challenge_value.encode("ascii")).hexdigest()
        )
        assert challenge.challenge_hash != issued.challenge_value
        assert issued.challenge_value not in repr(challenge)
        event = verification_session.scalar(
            select(SecurityAuditEvent).where(
                SecurityAuditEvent.target_id == issued.target_id,
                SecurityAuditEvent.action == "organization.target.created",
            )
        )
        assert event is not None
        assert event.details is None
        assert issued.challenge_value not in repr(event)


@pytest.mark.parametrize(
    "hostname",
    [
        "https://example.com",
        "*.example.com",
        "127.0.0.1",
        "0177.0.0.1",
        "example.com/path",
    ],
)
def test_target_creation_rejects_non_hostname_input_without_persisting(
    session: Session,
    make_user: Callable[..., User],
    hostname: str,
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()

    with pytest.raises(HostnameCanonicalizationError) as error:
        target_service(session).create_organization_target(
            principal,
            organization.id,
            hostname,
        )

    assert hostname not in str(error.value)
    with Session(session.get_bind()) as verification_session:
        assert (
            verification_session.scalar(
                select(SecurityTarget.id).where(SecurityTarget.organization_id == organization.id)
            )
            is None
        )


def test_owner_and_admin_can_manage_targets_but_phase_two_scan_policy_is_unchanged() -> None:
    for action in OrganizationTargetAction:
        assert all(
            allows_organization_target_action(role, action)
            for role in (OrganizationRole.OWNER, OrganizationRole.ADMIN)
        )
        assert not allows_organization_target_action(OrganizationRole.MEMBER, action)
        assert not allows_organization_target_action(OrganizationRole.VIEWER, action)
    assert allows_organization_scan_action(
        OrganizationRole.MEMBER,
        OrganizationScanAction.CREATE,
    )
    assert allows_organization_scan_action(
        OrganizationRole.VIEWER,
        OrganizationScanAction.READ,
    )


def test_member_cannot_create_organization_target(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, _ = create_organization_principal(
        session,
        make_user,
        role=OrganizationRole.MEMBER,
    )
    session.commit()

    with pytest.raises(OrganizationPermissionDenied):
        target_service(session).create_organization_target(
            principal,
            organization.id,
            "example.com",
        )

    with Session(session.get_bind()) as verification_session:
        assert (
            verification_session.scalar(
                select(SecurityTarget.id).where(SecurityTarget.organization_id == organization.id)
            )
            is None
        )


def test_duplicate_canonical_hostname_is_unique_within_organization(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, user = create_organization_principal(session, make_user)
    session.commit()
    service = target_service(session)
    service.create_organization_target(principal, organization.id, "Example.COM.")

    with pytest.raises(TargetConflict):
        service.create_organization_target(principal, organization.id, "example.com")

    with Session(session.get_bind()) as verification_session:
        verification_session.add(
            SecurityTarget(
                organization_id=organization.id,
                hostname="example.com",
                created_by_user_id=user.id,
            )
        )
        with pytest.raises(IntegrityError):
            verification_session.flush()


def test_challenge_rotation_consumption_is_one_time_and_does_not_verify_target(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()
    service = target_service(session)
    initial = service.create_organization_target(principal, organization.id, "example.com")
    rotated = service.rotate_challenge(principal, organization.id, initial.target_id)

    with Session(session.get_bind()) as verification_session:
        challenges = list(
            verification_session.scalars(
                select(TargetVerificationChallenge).where(
                    TargetVerificationChallenge.target_id == initial.target_id
                )
            ).all()
        )
        assert len(challenges) == 1
        assert (
            challenges[0].challenge_hash
            == sha256(rotated.challenge_value.encode("ascii")).hexdigest()
        )
        assert (
            challenges[0].challenge_hash
            != sha256(initial.challenge_value.encode("ascii")).hexdigest()
        )

    assert not service.consume_challenge_after_dns_proof(
        principal,
        organization.id,
        initial.target_id,
        "incorrect-value",
    )
    assert not service.consume_challenge_after_dns_proof(
        principal,
        organization.id,
        initial.target_id,
        "x" * 129,
    )
    assert not service.consume_challenge_after_dns_proof(
        principal,
        organization.id,
        initial.target_id,
        "\ud800",
    )
    assert not service.consume_challenge_after_dns_proof(
        principal,
        organization.id,
        initial.target_id,
        initial.challenge_value,
    )
    assert service.consume_challenge_after_dns_proof(
        principal,
        organization.id,
        initial.target_id,
        rotated.challenge_value,
    )
    assert not service.consume_challenge_after_dns_proof(
        principal,
        organization.id,
        initial.target_id,
        rotated.challenge_value,
    )

    with Session(session.get_bind()) as verification_session:
        target = verification_session.get(SecurityTarget, initial.target_id)
        assert target is not None
        assert target.verified_at is None
        assert (
            verification_session.scalar(
                select(TargetVerificationChallenge.id).where(
                    TargetVerificationChallenge.target_id == initial.target_id
                )
            )
            is None
        )


def test_expired_challenge_cannot_be_consumed(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()
    service = target_service(session)
    issued = service.create_organization_target(principal, organization.id, "example.com")
    with Session(session.get_bind()) as update_session:
        assert not TargetRepository(update_session).consume_challenge_after_dns_proof(
            organization.id,
            issued.target_id,
            issued.challenge_value,
            now=datetime.now(UTC) + timedelta(days=2),
        )
        assert (
            update_session.scalar(
                select(TargetVerificationChallenge.id).where(
                    TargetVerificationChallenge.target_id == issued.target_id
                )
            )
            is None
        )


def test_revoked_challenge_cannot_be_consumed(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    organization, principal, _ = create_organization_principal(session, make_user)
    session.commit()
    service = target_service(session)
    issued = service.create_organization_target(principal, organization.id, "example.com")
    with Session(session.get_bind()) as verification_session:
        challenge_id = get_challenge(verification_session, issued.target_id).id

    assert service.revoke_challenge(
        principal,
        organization.id,
        issued.target_id,
        challenge_id,
    )
    assert not service.consume_challenge_after_dns_proof(
        principal,
        organization.id,
        issued.target_id,
        issued.challenge_value,
    )
    with Session(session.get_bind()) as verification_session:
        assert (
            verification_session.scalar(
                select(TargetVerificationChallenge.id).where(
                    TargetVerificationChallenge.target_id == issued.target_id
                )
            )
            is None
        )


def test_challenge_and_target_queries_are_organization_scoped(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    first_organization, principal, user = create_organization_principal(session, make_user)
    second_organization, _, _ = create_organization_principal(session, make_user)
    session.commit()
    issued = target_service(session).create_organization_target(
        principal,
        first_organization.id,
        "example.com",
    )

    with Session(session.get_bind()) as verification_session:
        from threat_sentinel_api.modules.targets.repository import TargetRepository

        repository = TargetRepository(verification_session)
        assert repository.find_by_id(issued.target_id, second_organization.id) is None
        verification_session.add(
            TargetVerificationChallenge(
                organization_id=second_organization.id,
                target_id=issued.target_id,
                issued_by_user_id=user.id,
                challenge_hash="a" * 64,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        )
        with pytest.raises(IntegrityError):
            verification_session.flush()


def test_same_canonical_hostname_can_be_owned_by_different_organizations(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    first_organization, first_principal, _ = create_organization_principal(session, make_user)
    second_organization, second_principal, _ = create_organization_principal(session, make_user)
    session.commit()
    service = target_service(session)

    first = service.create_organization_target(
        first_principal,
        first_organization.id,
        "example.com",
    )
    second = service.create_organization_target(
        second_principal,
        second_organization.id,
        "example.com",
    )

    assert first.target_id != second.target_id


def test_challenge_consumption_does_not_accept_another_organizations_scope(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    first_organization, principal, _ = create_organization_principal(session, make_user)
    second_organization, _, _ = create_organization_principal(session, make_user)
    session.commit()
    issued = target_service(session).create_organization_target(
        principal,
        first_organization.id,
        "example.com",
    )
    with pytest.raises(OrganizationScopeUnavailable):
        target_service(session).consume_challenge_after_dns_proof(
            principal,
            second_organization.id,
            issued.target_id,
            issued.challenge_value,
        )
