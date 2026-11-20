from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session

from threat_sentinel_api.db.session import SessionFactory, unit_of_work
from threat_sentinel_api.modules.audit.recording import record_failure_event
from threat_sentinel_api.modules.audit.service import AuditService
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.identity.service import InactiveUserError
from threat_sentinel_api.modules.targets.dns_verification import (
    DNSChallengeVerification,
    DNSChallengeVerifier,
)
from threat_sentinel_api.modules.targets.hostname import (
    HostnameCanonicalizationError,
    canonicalize_hostname,
)
from threat_sentinel_api.modules.targets.models import SecurityTarget
from threat_sentinel_api.modules.targets.repository import TargetRepository
from threat_sentinel_api.modules.tenants.authorization import (
    OrganizationTargetAction,
    allows_organization_target_action,
)
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.service import (
    OrganizationAccessDenied,
    OrganizationPermissionDenied,
    OrganizationService,
)


@dataclass(frozen=True)
class IssuedTargetChallenge:
    target_id: UUID
    hostname: str
    expires_at: datetime
    challenge_value: str = field(repr=False)


class TargetNotFound(LookupError):
    """Raised when a target is absent from the requested organization."""


class TargetConflict(RuntimeError):
    """Raised when the organization already owns the canonical hostname."""


class TargetVerificationFailed(RuntimeError):
    """Raised when DNS ownership cannot be verified without disclosing DNS details."""

    def __init__(self) -> None:
        super().__init__("DNS ownership verification failed.")


class TargetService:
    def __init__(
        self,
        session_factory: SessionFactory | None = None,
        dns_verifier: DNSChallengeVerification | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._dns_verifier = dns_verifier if dns_verifier is not None else DNSChallengeVerifier()

    def create_organization_target(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        hostname: str,
    ) -> IssuedTargetChallenge:
        canonical_hostname = canonicalize_hostname(hostname)
        try:
            with unit_of_work(self._session_factory) as session:
                self._require_action(
                    session,
                    principal,
                    organization_id,
                    OrganizationTargetAction.CREATE,
                )
                repository = TargetRepository(session)
                if repository.find_by_hostname(organization_id, canonical_hostname) is not None:
                    raise TargetConflict("The organization already has this target.")
                target = repository.add_target(
                    organization_id,
                    canonical_hostname,
                    principal.user_id,
                )
                issued = self._issue(repository, target, principal.user_id)
                AuditService(session).record(
                    action="organization.target.created",
                    actor_user_id=principal.user_id,
                    organization_id=organization_id,
                    target_type="security_target",
                    target_id=target.id,
                )
                return issued
        except (InactiveUserError, OrganizationAccessDenied) as error:
            self._record_denial(
                principal,
                organization_id,
                "organization.target.create_denied",
                self._denial_reason(error),
            )
            raise

    def rotate_challenge(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        target_id: UUID,
    ) -> IssuedTargetChallenge:
        try:
            with unit_of_work(self._session_factory) as session:
                target = self._require_target_action(
                    session,
                    principal,
                    organization_id,
                    target_id,
                    OrganizationTargetAction.ROTATE_CHALLENGE,
                )
                issued = self._issue(TargetRepository(session), target, principal.user_id)
                AuditService(session).record(
                    action="organization.target.challenge_rotated",
                    actor_user_id=principal.user_id,
                    organization_id=organization_id,
                    target_type="security_target",
                    target_id=target.id,
                )
                return issued
        except (InactiveUserError, OrganizationAccessDenied, TargetNotFound) as error:
            self._record_denial(
                principal,
                organization_id,
                "organization.target.challenge_rotation_denied",
                self._denial_reason(error),
            )
            raise

    def revoke_challenge(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        target_id: UUID,
        challenge_id: UUID,
    ) -> bool:
        try:
            with unit_of_work(self._session_factory) as session:
                target = self._require_target_action(
                    session,
                    principal,
                    organization_id,
                    target_id,
                    OrganizationTargetAction.REVOKE_CHALLENGE,
                )
                revoked = TargetRepository(session).revoke_challenge(
                    organization_id,
                    target.id,
                    challenge_id,
                )
                AuditService(session).record(
                    action=(
                        "organization.target.challenge_revoked"
                        if revoked
                        else "organization.target.challenge_revocation_not_applied"
                    ),
                    actor_user_id=principal.user_id,
                    organization_id=organization_id,
                    target_type="security_target",
                    target_id=target.id,
                    outcome="success" if revoked else "failure",
                )
                return revoked
        except (InactiveUserError, OrganizationAccessDenied, TargetNotFound) as error:
            self._record_denial(
                principal,
                organization_id,
                "organization.target.challenge_revocation_denied",
                self._denial_reason(error),
            )
            raise

    def verify_organization_target(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        target_id: UUID,
    ) -> datetime:
        """Verify the active TXT challenge without holding database locks during DNS resolution."""
        try:
            with unit_of_work(self._session_factory) as session:
                self._require_action(
                    session,
                    principal,
                    organization_id,
                    OrganizationTargetAction.VERIFY,
                )
                repository = TargetRepository(session)
                target = repository.find_by_id(target_id, organization_id)
                if target is None:
                    raise TargetNotFound("The target was not found.")
                if target.verified_at is not None:
                    raise TargetVerificationFailed()
                challenge = repository.find_active_challenge(
                    organization_id,
                    target.id,
                )
                if challenge is None:
                    raise TargetVerificationFailed()
                hostname = target.hostname
                challenge_id = challenge.id
                challenge_hash = challenge.challenge_hash
        except (InactiveUserError, OrganizationAccessDenied, TargetNotFound) as error:
            self._record_denial(
                principal,
                organization_id,
                "organization.target.verification_denied",
                self._denial_reason(error),
            )
            raise

        try:
            canonical_hostname = canonicalize_hostname(hostname)
        except HostnameCanonicalizationError:
            raise TargetVerificationFailed() from None

        try:
            self._dns_verifier.verify_challenge(canonical_hostname, challenge_hash)
        except Exception:
            raise TargetVerificationFailed() from None

        try:
            with unit_of_work(self._session_factory) as session:
                target = self._require_target_action(
                    session,
                    principal,
                    organization_id,
                    target_id,
                    OrganizationTargetAction.VERIFY,
                )
                if target.verified_at is not None or target.hostname != hostname:
                    raise TargetVerificationFailed()
                verified_at = datetime.now(UTC)
                verified = TargetRepository(session).verify_target_after_dns_proof(
                    target,
                    organization_id,
                    challenge_id,
                    challenge_hash,
                    now=verified_at,
                )
                if not verified:
                    raise TargetVerificationFailed()
                AuditService(session).record(
                    action="organization.target.verified",
                    actor_user_id=principal.user_id,
                    organization_id=organization_id,
                    target_type="security_target",
                    target_id=target.id,
                )
        except (InactiveUserError, OrganizationAccessDenied, TargetNotFound) as error:
            self._record_denial(
                principal,
                organization_id,
                "organization.target.verification_denied",
                self._denial_reason(error),
            )
            raise
        return verified_at

    @staticmethod
    def _issue(
        repository: TargetRepository,
        target: SecurityTarget,
        actor_user_id: UUID,
    ) -> IssuedTargetChallenge:
        challenge, challenge_value = repository.issue_challenge(target, actor_user_id)
        return IssuedTargetChallenge(
            target_id=target.id,
            hostname=target.hostname,
            expires_at=challenge.expires_at,
            challenge_value=challenge_value,
        )

    @staticmethod
    def _require_action(
        session: Session,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        action: OrganizationTargetAction,
    ) -> None:
        membership = OrganizationService(OrganizationRepository(session)).require_active_membership(
            principal,
            organization_id,
        )
        if not allows_organization_target_action(membership.role, action):
            raise OrganizationPermissionDenied(
                "The user is not authorized to manage organization targets."
            )

    @classmethod
    def _require_target_action(
        cls,
        session: Session,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        target_id: UUID,
        action: OrganizationTargetAction,
    ) -> SecurityTarget:
        cls._require_action(session, principal, organization_id, action)
        target = TargetRepository(session).find_by_id(
            target_id,
            organization_id,
            for_update=True,
        )
        if target is None:
            raise TargetNotFound("The target was not found.")
        return target

    def _record_denial(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        action: str,
        reason: str,
    ) -> None:
        record_failure_event(
            principal,
            action,
            reason,
            organization_id=organization_id,
            unit_of_work_factory=lambda: unit_of_work(self._session_factory),
        )

    @staticmethod
    def _denial_reason(error: Exception) -> str:
        if isinstance(error, OrganizationPermissionDenied):
            return "insufficient_role"
        if isinstance(error, InactiveUserError):
            return "inactive_account"
        if isinstance(error, TargetNotFound):
            return "resource_unavailable"
        return "scope_unavailable"
