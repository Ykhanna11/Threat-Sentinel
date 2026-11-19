from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import secrets
from uuid import UUID

from sqlalchemy.orm import Session

from threat_sentinel_api.modules.audit.service import AuditService
from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.models import User
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.identity.service import InactiveUserError
from threat_sentinel_api.modules.tenants.enums import (
    InvitationStatus,
    MembershipStatus,
    OrganizationRole,
    OrganizationStatus,
)
from threat_sentinel_api.modules.tenants.invariants import (
    require_active_owner,
    require_active_owner_after_changes,
)
from threat_sentinel_api.modules.tenants.lifecycle_repository import (
    OrganizationLifecycleRepository,
)
from threat_sentinel_api.modules.tenants.models import (
    Organization,
    OrganizationInvitation,
    OrganizationMembership,
)
from threat_sentinel_api.modules.tenants.schemas import (
    InvitationCreate,
    MembershipUpdate,
    OrganizationMemberResponse,
    OrganizationUpdate,
    SecurityAuditEventResponse,
)
from threat_sentinel_api.modules.tenants.service import (
    OrganizationConflict,
    OrganizationPermissionDenied,
    OrganizationScopeUnavailable,
)

INVITATION_TTL = timedelta(days=7)


@dataclass(frozen=True)
class VerifiedInvitationRecipient:
    identity_id: UUID
    user_id: UUID


class MembershipNotFound(LookupError):
    """Raised when a membership is not present in the requested organization."""


class InvitationUnavailable(LookupError):
    """Raised when an invitation token is missing, invalid, expired, or consumed."""


class OrganizationLifecycleService:
    def __init__(self, session: Session) -> None:
        self._session = session
        self._repository = OrganizationLifecycleRepository(session)
        self._audit = AuditService(session)

    def list_members(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
    ) -> list[OrganizationMemberResponse]:
        user = self._repository.lock_principal_user_for_share(principal)
        if user is None or user.status is not UserStatus.ACTIVE:
            raise InactiveUserError("The linked account is not active.")
        organization = self._repository.lock_organization_for_share(organization_id)
        if organization is None or organization.status is not OrganizationStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")

        memberships = self._repository.lock_memberships_for_share(organization_id)
        actor_membership = self._membership_for_user(memberships, user.id)
        if actor_membership is None or actor_membership.status is not MembershipStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        display_names: dict[UUID, str | None] = {}
        for member in memberships:
            user = self._session.get(User, member.user_id)
            display_names[member.user_id] = user.display_name if user is not None else None
        return [
            OrganizationMemberResponse(
                membership_id=member.id,
                display_name=display_names[member.user_id],
                role=member.role,
                status=member.status,
                created_at=member.created_at,
            )
            for member in memberships
        ]

    def update_organization(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        update: OrganizationUpdate,
    ) -> Organization:
        users = self._repository.lock_principal_users_for_update(principal)
        self._require_active_user(users[principal.user_id])
        organization = self._repository.lock_organization_for_update(organization_id)
        if organization is None or organization.status is not OrganizationStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        memberships = self._repository.lock_memberships_for_update(organization_id)
        actor_membership = self._require_active_membership(memberships, principal.user_id)
        self._require_management_role(actor_membership.role)

        if update.slug is not None and update.slug != organization.slug:
            from threat_sentinel_api.modules.tenants.repository import OrganizationRepository

            if OrganizationRepository(self._session).slug_exists(update.slug):
                raise OrganizationConflict("An organization with that slug already exists.")
            organization.slug = update.slug
        if update.name is not None:
            organization.name = update.name
        self._session.flush()
        self._audit.record(
            action="organization.updated",
            actor_user_id=principal.user_id,
            organization_id=organization.id,
            target_type="organization",
            target_id=organization.id,
        )
        return organization

    def suspend_organization(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
    ) -> Organization:
        users = self._repository.lock_principal_users_for_update(principal)
        self._require_active_user(users[principal.user_id])
        organization = self._repository.lock_organization_for_update(organization_id)
        if organization is None:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        invitations = self._repository.lock_invitations_for_update(organization_id)
        memberships = self._repository.lock_memberships_for_update(organization_id)
        actor_membership = self._require_active_membership(memberships, principal.user_id)
        if actor_membership.role is not OrganizationRole.OWNER:
            raise OrganizationPermissionDenied("The user cannot change organization lifecycle.")
        if organization.status is not OrganizationStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        if organization.status is OrganizationStatus.ACTIVE:
            organization.status = OrganizationStatus.SUSPENDED
            now = datetime.now(UTC)
            for invitation in invitations:
                if invitation.status is InvitationStatus.PENDING:
                    invitation.status = InvitationStatus.REVOKED
                    invitation.revoked_at = now
            self._session.flush()
            self._audit.record(
                action="organization.suspended",
                actor_user_id=principal.user_id,
                organization_id=organization.id,
                target_type="organization",
                target_id=organization.id,
            )
        return organization

    def reactivate_organization(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
    ) -> Organization:
        users = self._repository.lock_principal_users_for_update(principal)
        self._require_active_user(users[principal.user_id])
        organization = self._repository.lock_organization_for_update(organization_id)
        if organization is None:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        memberships = self._repository.lock_memberships_for_update(organization_id)
        actor_membership = self._require_active_membership(memberships, principal.user_id)
        if actor_membership.role is not OrganizationRole.OWNER:
            raise OrganizationPermissionDenied("The user cannot change organization lifecycle.")
        if organization.status is not OrganizationStatus.SUSPENDED:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        organization.status = OrganizationStatus.ACTIVE
        self._session.flush()
        self._audit.record(
            action="organization.reactivated",
            actor_user_id=principal.user_id,
            organization_id=organization.id,
            target_type="organization",
            target_id=organization.id,
        )
        return organization

    def archive_organization(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
    ) -> Organization:
        users = self._repository.lock_principal_users_for_update(principal)
        self._require_active_user(users[principal.user_id])
        organization = self._repository.lock_organization_for_update(organization_id)
        if organization is None:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        invitations = self._repository.lock_invitations_for_update(organization_id)
        memberships = self._repository.lock_memberships_for_update(organization_id)
        actor_membership = self._require_active_membership(memberships, principal.user_id)
        if actor_membership.role is not OrganizationRole.OWNER:
            raise OrganizationPermissionDenied("The user cannot change organization lifecycle.")
        if organization.status is not OrganizationStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        if not self._repository.has_active_owner(organization_id):
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        now = datetime.now(UTC)
        organization.status = OrganizationStatus.ARCHIVED
        for invitation in invitations:
            if invitation.status is InvitationStatus.PENDING:
                invitation.status = InvitationStatus.REVOKED
                invitation.revoked_at = now
        self._session.flush()
        self._audit.record(
            action="organization.archived",
            actor_user_id=principal.user_id,
            organization_id=organization.id,
            target_type="organization",
            target_id=organization.id,
        )
        return organization

    def restore_organization(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
    ) -> Organization:
        users = self._repository.lock_principal_users_for_update(principal)
        self._require_active_user(users[principal.user_id])
        organization = self._repository.lock_organization_for_update(organization_id)
        if organization is None or organization.status is not OrganizationStatus.ARCHIVED:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        memberships = self._repository.lock_memberships_for_update(organization_id)
        actor_membership = self._require_active_membership(memberships, principal.user_id)
        if actor_membership.role is not OrganizationRole.OWNER:
            raise OrganizationPermissionDenied("The user cannot change organization lifecycle.")
        if not self._repository.has_active_owner(organization_id):
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        organization.status = OrganizationStatus.ACTIVE
        self._session.flush()
        self._audit.record(
            action="organization.restored",
            actor_user_id=principal.user_id,
            organization_id=organization.id,
            target_type="organization",
            target_id=organization.id,
        )
        return organization

    def update_membership(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        membership_id: UUID,
        update: MembershipUpdate,
    ) -> OrganizationMembership:
        target_user_id = self._repository.find_membership_user_id(organization_id, membership_id)
        if target_user_id is None:
            raise MembershipNotFound("The membership was not found.")
        users = self._repository.lock_principal_users_for_update(
            principal,
            (target_user_id,),
        )
        self._require_active_user(users[principal.user_id])
        target_user = users.get(target_user_id)
        if target_user is None:
            raise MembershipNotFound("The membership was not found.")
        organization = self._repository.lock_organization_for_update(organization_id)
        if organization is None or organization.status is not OrganizationStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        memberships = self._repository.lock_memberships_for_update(organization_id)
        actor_membership = self._require_active_membership(memberships, principal.user_id)
        target = self._membership_by_id(memberships, membership_id)
        if target is None or target.user_id != target_user_id:
            raise MembershipNotFound("The membership was not found.")
        if target.user_id == principal.user_id or target.role is OrganizationRole.OWNER:
            raise OrganizationPermissionDenied(
                "The membership cannot be changed by this operation."
            )
        self._require_can_manage_target(actor_membership.role, target.role)
        if update.role is OrganizationRole.OWNER:
            raise OrganizationPermissionDenied("Ownership changes require an ownership transfer.")
        if target.status is MembershipStatus.REMOVED:
            raise OrganizationConflict("A removed membership cannot be changed directly.")
        if update.status is MembershipStatus.ACTIVE and target_user.status is not UserStatus.ACTIVE:
            raise InactiveUserError("The linked account is not active.")

        new_role = update.role or target.role
        new_status = update.status or target.status
        require_active_owner_after_changes(
            memberships,
            {target.id: (new_role, new_status)},
        )
        if update.role is not None:
            target.role = update.role
        if update.status is not None:
            target.status = update.status
        self._session.flush()
        self._audit.record(
            action="membership.updated",
            actor_user_id=principal.user_id,
            organization_id=organization_id,
            target_type="membership",
            target_id=target.id,
            details={"role": new_role.value, "status": new_status.value},
        )
        return target

    def transfer_ownership(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        membership_id: UUID,
    ) -> tuple[OrganizationMembership, OrganizationMembership]:
        target_user_id = self._repository.find_membership_user_id(organization_id, membership_id)
        if target_user_id is None or target_user_id == principal.user_id:
            raise MembershipNotFound("The membership was not found.")
        users = self._repository.lock_principal_users_for_update(
            principal,
            (target_user_id,),
        )
        self._require_active_user(users[principal.user_id])
        if users[target_user_id].status is not UserStatus.ACTIVE:
            raise InactiveUserError("The linked account is not active.")
        organization = self._repository.lock_organization_for_update(organization_id)
        if organization is None or organization.status is not OrganizationStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        memberships = self._repository.lock_memberships_for_update(organization_id)
        owner_membership = self._require_active_membership(memberships, principal.user_id)
        target_membership = self._membership_by_id(memberships, membership_id)
        if target_membership is None or target_membership.user_id != target_user_id:
            raise MembershipNotFound("The membership was not found.")
        if owner_membership.role is not OrganizationRole.OWNER:
            raise OrganizationPermissionDenied("Only an owner can transfer ownership.")
        if target_membership.status is not MembershipStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")

        require_active_owner_after_changes(
            memberships,
            {
                owner_membership.id: (OrganizationRole.ADMIN, owner_membership.status),
                target_membership.id: (OrganizationRole.OWNER, target_membership.status),
            },
        )
        target_membership.role = OrganizationRole.OWNER
        owner_membership.role = OrganizationRole.ADMIN
        self._session.flush()
        self._audit.record(
            action="organization.ownership_transferred",
            actor_user_id=principal.user_id,
            organization_id=organization_id,
            target_type="membership",
            target_id=target_membership.id,
        )
        return owner_membership, target_membership

    def authorize_invitation(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        details: InvitationCreate,
    ) -> VerifiedInvitationRecipient:
        users = self._repository.lock_principal_users_for_update(principal)
        self._require_active_user(users[principal.user_id])
        organization = self._repository.lock_organization_for_update(organization_id)
        if organization is None or organization.status is not OrganizationStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        memberships = self._repository.lock_memberships_for_update(organization_id)
        actor_membership = self._require_active_membership(memberships, principal.user_id)
        self._require_can_invite(actor_membership.role, details.role)

        intended_identity = self._repository.find_verified_identity_for_email(details.email)
        if intended_identity is None:
            raise InvitationUnavailable("The invitation is unavailable.")
        identity_id, user_id = intended_identity
        if user_id == principal.user_id:
            raise OrganizationPermissionDenied("The user cannot invite their own account.")
        return VerifiedInvitationRecipient(identity_id=identity_id, user_id=user_id)

    def create_invitation(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        details: InvitationCreate,
        recipient: VerifiedInvitationRecipient,
    ) -> tuple[OrganizationInvitation, str]:
        if recipient.user_id == principal.user_id:
            raise OrganizationPermissionDenied("The user cannot invite their own account.")
        users = self._repository.lock_principal_users_for_update(
            principal,
            (recipient.user_id,),
        )
        self._require_active_user(users[principal.user_id])
        intended_user = users.get(recipient.user_id)
        if (
            intended_user is None
            or intended_user.status is not UserStatus.ACTIVE
            or not self._repository.is_verified_identity_for_email(
                recipient.identity_id,
                recipient.user_id,
                details.email,
            )
        ):
            raise InvitationUnavailable("The invitation is unavailable.")
        organization = self._repository.lock_organization_for_update(organization_id)
        if organization is None or organization.status is not OrganizationStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        invitations = self._repository.lock_invitations_for_update(organization_id)
        memberships = self._repository.lock_memberships_for_update(organization_id)
        actor_membership = self._require_active_membership(memberships, principal.user_id)
        self._require_can_invite(actor_membership.role, details.role)
        existing_membership = self._membership_for_user(memberships, recipient.user_id)
        if (
            existing_membership is not None
            and existing_membership.status is MembershipStatus.ACTIVE
        ):
            raise OrganizationConflict("A pending invitation already exists.")

        now = datetime.now(UTC)
        for invitation in invitations:
            if invitation.status is not InvitationStatus.PENDING:
                continue
            if _as_utc(invitation.expires_at) <= now:
                invitation.status = InvitationStatus.EXPIRED
                self._session.flush()
            elif invitation.intended_email.strip().lower() == details.email:
                raise OrganizationConflict("A pending invitation already exists.")

        token = secrets.token_urlsafe(32)
        invitation = OrganizationInvitation(
            organization_id=organization_id,
            inviter_user_id=principal.user_id,
            intended_email=details.email,
            intended_identity_id=recipient.identity_id,
            token_hash=sha256(token.encode("ascii")).hexdigest(),
            role=details.role,
            expires_at=now + INVITATION_TTL,
        )
        self._repository.add_invitation(invitation)
        self._audit.record(
            action="invitation.created",
            actor_user_id=principal.user_id,
            organization_id=organization_id,
            target_type="invitation",
            target_id=invitation.id,
            details={"role": details.role.value},
        )
        return invitation, token

    def revoke_invitation(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        invitation_id: UUID,
    ) -> None:
        users = self._repository.lock_principal_users_for_update(principal)
        self._require_active_user(users[principal.user_id])
        organization = self._repository.lock_organization_for_update(organization_id)
        if organization is None or organization.status is not OrganizationStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        invitation = self._repository.lock_invitation_for_update(
            invitation_id,
            organization_id,
        )
        if invitation is None or invitation.status is not InvitationStatus.PENDING:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        memberships = self._repository.lock_memberships_for_update(organization_id)
        actor_membership = self._require_active_membership(memberships, principal.user_id)
        self._require_can_invite(actor_membership.role, invitation.role)
        invitation.status = InvitationStatus.REVOKED
        invitation.revoked_at = datetime.now(UTC)
        self._session.flush()
        self._audit.record(
            action="invitation.revoked",
            actor_user_id=principal.user_id,
            organization_id=organization_id,
            target_type="invitation",
            target_id=invitation.id,
        )

    def accept_invitation(
        self,
        principal: AuthenticatedPrincipal,
        token: str,
    ) -> OrganizationMembership | None:
        token_hash = sha256(token.encode("ascii")).hexdigest()
        location = self._repository.find_invitation_location(token_hash)
        if location is None:
            return None
        invitation_id, organization_id = location

        users = self._repository.lock_principal_users_for_update(principal)
        self._require_active_user(users[principal.user_id])
        organization = self._repository.lock_organization_for_update(organization_id)
        if organization is None:
            return None
        invitation = self._repository.lock_invitation_for_update(invitation_id, organization_id)
        if (
            invitation is None
            or invitation.token_hash != token_hash
            or invitation.status is not InvitationStatus.PENDING
        ):
            return None

        now = datetime.now(UTC)
        if _as_utc(invitation.expires_at) <= now:
            invitation.status = InvitationStatus.EXPIRED
            self._session.flush()
            return None
        email = principal.email.strip().lower() if principal.email is not None else None
        if (
            organization.status is not OrganizationStatus.ACTIVE
            or principal.external_identity_id != invitation.intended_identity_id
            or not principal.email_verified
            or email != invitation.intended_email.strip().lower()
        ):
            return None

        memberships = self._repository.lock_memberships_for_update(organization_id)
        existing = self._membership_for_user(memberships, principal.user_id)
        if existing is not None and existing.status is MembershipStatus.ACTIVE:
            return None
        if existing is not None and existing.role is OrganizationRole.OWNER:
            return None
        if existing is None:
            membership = OrganizationMembership(
                organization_id=organization_id,
                user_id=principal.user_id,
                role=invitation.role,
                status=MembershipStatus.ACTIVE,
            )
            self._session.add(membership)
            self._session.flush()
            memberships.append(membership)
        else:
            existing.role = invitation.role
            existing.status = MembershipStatus.ACTIVE
            membership = existing

        require_active_owner(memberships)
        invitation.status = InvitationStatus.ACCEPTED
        invitation.accepted_at = now
        invitation.accepted_membership_id = membership.id
        self._session.flush()
        self._audit.record(
            action="invitation.accepted",
            actor_user_id=principal.user_id,
            organization_id=organization_id,
            target_type="membership",
            target_id=membership.id,
        )
        return membership

    def list_audit_events(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        limit: int,
    ) -> list[SecurityAuditEventResponse]:
        users = self._repository.lock_principal_users_for_update(principal)
        self._require_active_user(users[principal.user_id])
        organization = self._repository.lock_organization_for_share(organization_id)
        if organization is None:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        if organization.status is not OrganizationStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        memberships = self._repository.lock_memberships_for_share(organization_id)
        actor_membership = self._require_active_membership(memberships, principal.user_id)
        self._require_management_role(actor_membership.role)
        events = self._audit.list_organization_events(
            organization_id,
            limit=min(limit, 100),
        )
        return [
            SecurityAuditEventResponse(
                id=event.id,
                created_at=event.created_at,
                actor_user_id=event.actor_user_id,
                organization_id=event.organization_id,
                action=event.action,
                outcome=event.outcome,
                target_type=event.target_type,
                target_id=event.target_id,
                request_id=event.request_id,
            )
            for event in events
        ]

    @staticmethod
    def _require_active_user(user: User) -> None:
        if user.status is not UserStatus.ACTIVE:
            raise InactiveUserError("The linked account is not active.")

    @staticmethod
    def _membership_for_user(
        memberships: list[OrganizationMembership],
        user_id: UUID,
    ) -> OrganizationMembership | None:
        return next((member for member in memberships if member.user_id == user_id), None)

    @staticmethod
    def _membership_by_id(
        memberships: list[OrganizationMembership],
        membership_id: UUID,
    ) -> OrganizationMembership | None:
        return next((member for member in memberships if member.id == membership_id), None)

    @classmethod
    def _require_active_membership(
        cls,
        memberships: list[OrganizationMembership],
        user_id: UUID,
    ) -> OrganizationMembership:
        membership = cls._membership_for_user(memberships, user_id)
        if membership is None or membership.status is not MembershipStatus.ACTIVE:
            raise OrganizationScopeUnavailable("The requested organization scope is unavailable.")
        return membership

    @staticmethod
    def _require_management_role(role: OrganizationRole) -> None:
        if role not in {OrganizationRole.OWNER, OrganizationRole.ADMIN}:
            raise OrganizationPermissionDenied("The user cannot manage this organization.")

    @classmethod
    def _require_can_manage_target(
        cls,
        actor_role: OrganizationRole,
        target_role: OrganizationRole,
    ) -> None:
        cls._require_management_role(actor_role)
        allowed = (
            target_role
            in {OrganizationRole.ADMIN, OrganizationRole.MEMBER, OrganizationRole.VIEWER}
            if actor_role is OrganizationRole.OWNER
            else target_role in {OrganizationRole.MEMBER, OrganizationRole.VIEWER}
        )
        if not allowed:
            raise OrganizationPermissionDenied("The user cannot manage this membership.")

    @classmethod
    def _require_can_invite(
        cls,
        actor_role: OrganizationRole,
        invited_role: OrganizationRole,
    ) -> None:
        cls._require_management_role(actor_role)
        allowed_roles = (
            {OrganizationRole.ADMIN, OrganizationRole.MEMBER, OrganizationRole.VIEWER}
            if actor_role is OrganizationRole.OWNER
            else {OrganizationRole.MEMBER, OrganizationRole.VIEWER}
        )
        if invited_role not in allowed_roles:
            raise OrganizationPermissionDenied("The user cannot grant the requested role.")


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
