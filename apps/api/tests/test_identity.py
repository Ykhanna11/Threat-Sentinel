from datetime import UTC, datetime
from collections.abc import Callable

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import VerifiedUserContext
from threat_sentinel_api.modules.identity.service import IdentityService, InactiveUserError
from threat_sentinel_api.modules.tenants.models import OrganizationMembership


def test_external_identity_resolves_same_internal_user(session: Session) -> None:
    service = IdentityService(IdentityRepository(session))
    context = VerifiedUserContext(
        issuer="https://issuer.example",
        subject="subject-123",
    )

    first = service.resolve_verified_user(context)
    second = service.resolve_verified_user(context)

    assert first.id == second.id
    assert session.scalar(select(func.count()).select_from(User)) == 1
    assert session.scalar(select(func.count()).select_from(ExternalIdentity)) == 1


def test_email_is_not_used_for_identity_linking_and_verification_is_explicit(
    session: Session,
) -> None:
    service = IdentityService(IdentityRepository(session))
    shared_email = "same@example.test"

    unverified = service.resolve_verified_user(
        VerifiedUserContext(
            issuer="https://issuer.example",
            subject="unverified-subject",
            email=shared_email,
        )
    )
    verified = service.resolve_verified_user(
        VerifiedUserContext(
            issuer="https://issuer.example",
            subject="verified-subject",
            email=shared_email,
            email_verified=True,
        )
    )
    session.flush()

    assert unverified.id != verified.id
    assert (
        session.scalar(
            select(ExternalIdentity.email_verified_at).where(
                ExternalIdentity.user_id == unverified.id
            )
        )
        is None
    )
    assert (
        session.scalar(
            select(ExternalIdentity.email_verified_at).where(
                ExternalIdentity.user_id == verified.id
            )
        )
        is not None
    )
    assert session.scalar(select(func.count()).select_from(OrganizationMembership)) == 0


def test_issuer_subject_pair_is_unique(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    user = make_user(issuer="https://issuer.example", subject="unique-subject")
    duplicate_owner = User()
    session.add(duplicate_owner)
    session.flush()
    session.add(
        ExternalIdentity(
            user_id=user.id,
            issuer="https://issuer.example",
            subject="unique-subject",
        )
    )

    with pytest.raises(IntegrityError):
        session.flush()


def test_existing_verified_email_is_cleared_if_identity_email_changes_unverified(
    session: Session,
) -> None:
    service = IdentityService(IdentityRepository(session))
    user = service.resolve_verified_user(
        VerifiedUserContext(
            issuer="https://issuer.example",
            subject="subject",
            email="old@example.test",
            email_verified=True,
        )
    )
    identity = session.scalar(select(ExternalIdentity).where(ExternalIdentity.user_id == user.id))
    assert identity is not None
    assert identity.email_verified_at is not None

    service.resolve_verified_user(
        VerifiedUserContext(
            issuer="https://issuer.example",
            subject="subject",
            email="new@example.test",
            email_verified=False,
        )
    )

    assert identity.email == "new@example.test"
    assert identity.email_verified_at is None


def test_same_email_becoming_unverified_clears_verification_timestamp(
    session: Session,
) -> None:
    service = IdentityService(IdentityRepository(session))
    user = service.resolve_verified_user(
        VerifiedUserContext(
            issuer="https://issuer.example",
            subject="same-email",
            email="person@example.test",
            email_verified=True,
        )
    )
    identity = session.scalar(select(ExternalIdentity).where(ExternalIdentity.user_id == user.id))
    assert identity is not None
    assert identity.email_verified_at is not None

    service.resolve_verified_user(
        VerifiedUserContext(
            issuer="https://issuer.example",
            subject="same-email",
            email="person@example.test",
            email_verified=False,
        )
    )

    assert identity.email == "person@example.test"
    assert identity.email_verified_at is None


def test_missing_email_preserves_existing_email_metadata(session: Session) -> None:
    service = IdentityService(IdentityRepository(session))
    user = service.resolve_verified_user(
        VerifiedUserContext(
            issuer="https://issuer.example",
            subject="email-omitted",
            email="person@example.test",
            email_verified=True,
        )
    )
    identity = session.scalar(select(ExternalIdentity).where(ExternalIdentity.user_id == user.id))
    assert identity is not None
    verified_at = identity.email_verified_at

    service.resolve_verified_user(
        VerifiedUserContext(
            issuer="https://issuer.example",
            subject="email-omitted",
        )
    )

    assert identity.email == "person@example.test"
    assert identity.email_verified_at == verified_at


def test_new_verified_email_updates_email_and_verification_timestamp(session: Session) -> None:
    service = IdentityService(IdentityRepository(session))
    user = service.resolve_verified_user(
        VerifiedUserContext(
            issuer="https://issuer.example",
            subject="email-update",
            email="old@example.test",
            email_verified=True,
        )
    )
    identity = session.scalar(select(ExternalIdentity).where(ExternalIdentity.user_id == user.id))
    assert identity is not None
    previous_verification = datetime(2020, 1, 1, tzinfo=UTC)
    identity.email_verified_at = previous_verification

    service.resolve_verified_user(
        VerifiedUserContext(
            issuer="https://issuer.example",
            subject="email-update",
            email="new@example.test",
            email_verified=True,
        )
    )

    assert identity.email == "new@example.test"
    assert identity.email_verified_at is not None
    assert identity.email_verified_at > previous_verification


def test_verified_context_cannot_mark_an_absent_email_as_verified() -> None:
    with pytest.raises(ValidationError):
        VerifiedUserContext(
            issuer="https://issuer.example",
            subject="subject",
            email_verified=True,
        )


def test_provider_role_claims_are_not_part_of_the_application_context() -> None:
    with pytest.raises(ValidationError):
        VerifiedUserContext.model_validate(
            {
                "issuer": "https://issuer.example",
                "subject": "subject",
                "roles": ["admin"],
            }
        )


def test_inactive_local_user_cannot_be_resolved(
    session: Session,
    make_user: Callable[..., User],
) -> None:
    user = make_user(subject="inactive-subject")
    user.status = UserStatus.SUSPENDED
    session.flush()

    service = IdentityService(IdentityRepository(session))
    with pytest.raises(InactiveUserError):
        service.resolve_verified_user(
            VerifiedUserContext(
                issuer="https://identity.example",
                subject="inactive-subject",
            )
        )
