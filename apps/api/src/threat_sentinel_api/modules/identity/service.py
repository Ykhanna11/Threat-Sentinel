from datetime import UTC, datetime

from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import (
    AuthenticatedPrincipal,
    VerifiedAccessTokenClaims,
    VerifiedUserContext,
)


class InvalidPrincipalError(PermissionError):
    """Raised when an authenticated principal no longer matches an active local identity."""


class InactiveUserError(InvalidPrincipalError):
    """Raised when an external identity is linked to a non-active local user."""


class IdentityService:
    def __init__(self, repository: IdentityRepository) -> None:
        self._repository = repository

    def resolve_verified_user(self, context: VerifiedUserContext) -> User:
        identity_link = self._repository.find_identity_link(context.issuer, context.subject)
        if identity_link is not None:
            locked_identity = self._repository.lock_user_for_identity_share(
                context.issuer,
                context.subject,
            )
            if locked_identity is None:
                raise InvalidPrincipalError("The authenticated principal is no longer valid.")
            identity_id, user = locked_identity
            if user.status is not UserStatus.ACTIVE:
                raise InactiveUserError("The linked account is not active.")
            identity = self._repository.find_by_issuer_subject(context.issuer, context.subject)
            if identity is None or identity.id != identity_id or identity.user_id != user.id:
                raise InvalidPrincipalError("The authenticated principal is no longer valid.")
            self._refresh_email_metadata(identity, context)
            return user

        user = User()
        self._repository.add(
            ExternalIdentity(
                user=user,
                issuer=context.issuer,
                subject=context.subject,
                email=context.email,
                email_verified_at=self._verified_at(context),
            )
        )
        return user

    def resolve_authenticated_principal(
        self,
        claims: VerifiedAccessTokenClaims,
    ) -> AuthenticatedPrincipal:
        """Resolve verifier-produced claims to an active local identity."""
        context = VerifiedUserContext(
            issuer=claims.issuer,
            subject=claims.subject,
            email=claims.email,
            email_verified=claims.email_verified is True,
        )
        user = self.resolve_verified_user(context)
        identity_link = self._repository.find_identity_link(context.issuer, context.subject)
        if (
            user.status is not UserStatus.ACTIVE
            or identity_link is None
            or identity_link[1] != user.id
        ):
            raise InvalidPrincipalError("The authenticated principal is no longer valid.")
        identity = self._repository.find_by_issuer_subject(context.issuer, context.subject)
        if identity is None or identity.id != identity_link[0] or identity.user_id != user.id:
            raise InvalidPrincipalError("The authenticated principal is no longer valid.")

        return AuthenticatedPrincipal(
            user_id=user.id,
            external_identity_id=identity.id,
            issuer=identity.issuer,
            subject=identity.subject,
            email=identity.email,
            email_verified=identity.email_verified_at is not None,
        )

    @staticmethod
    def _verified_at(context: VerifiedUserContext) -> datetime | None:
        if context.email is not None and context.email_verified:
            return datetime.now(UTC)
        return None

    @classmethod
    def _refresh_email_metadata(
        cls,
        identity: ExternalIdentity,
        context: VerifiedUserContext,
    ) -> None:
        if context.email is None:
            return

        email_changed = identity.email != context.email
        identity.email = context.email
        if not context.email_verified:
            identity.email_verified_at = None
        elif email_changed or identity.email_verified_at is None:
            identity.email_verified_at = datetime.now(UTC)
