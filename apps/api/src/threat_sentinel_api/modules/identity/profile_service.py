from sqlalchemy import select

from threat_sentinel_api.modules.audit.service import AuditService
from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import (
    AccountExportMembership,
    AccountExportResponse,
    AccountProfileResponse,
    AccountProfileUpdate,
    AuthenticatedPrincipal,
)
from threat_sentinel_api.modules.identity.service import InactiveUserError
from threat_sentinel_api.modules.tenants.models import OrganizationMembership


class AccountProfileService:
    def __init__(self, repository: IdentityRepository) -> None:
        self._repository = repository
        self._audit = AuditService(repository.session)

    def get_profile(self, principal: AuthenticatedPrincipal) -> AccountProfileResponse:
        linked_identity = self._repository.lock_user_for_identity_share(
            principal.issuer,
            principal.subject,
        )
        if linked_identity is None:
            raise InactiveUserError("The linked account is not active.")
        identity_id, user = linked_identity
        if (
            identity_id != principal.external_identity_id
            or user.id != principal.user_id
            or user.status is not UserStatus.ACTIVE
        ):
            raise InactiveUserError("The linked account is not active.")
        return AccountProfileResponse(
            display_name=user.display_name,
            created_at=user.created_at,
        )

    def update_profile(
        self,
        principal: AuthenticatedPrincipal,
        update: AccountProfileUpdate,
    ) -> AccountProfileResponse:
        user = self._repository.lock_user_for_principal_update(principal)
        if user is None or user.status is not UserStatus.ACTIVE:
            raise InactiveUserError("The linked account is not active.")
        user.display_name = update.display_name
        self._repository.flush()
        return AccountProfileResponse(
            display_name=user.display_name,
            created_at=user.created_at,
        )

    def export_account(self, principal: AuthenticatedPrincipal) -> AccountExportResponse:
        user = self._repository.lock_user_for_principal_update(principal)
        if user is None or user.status is not UserStatus.ACTIVE:
            raise InactiveUserError("The linked account is not active.")
        membership_rows = self._repository.session.scalars(
            select(OrganizationMembership)
            .where(OrganizationMembership.user_id == user.id)
            .order_by(OrganizationMembership.organization_id)
        ).all()
        memberships = tuple(
            AccountExportMembership(
                organization_id=membership.organization_id,
                membership_id=membership.id,
                role=membership.role.value,
                status=membership.status.value,
                created_at=membership.created_at,
            )
            for membership in membership_rows
        )
        export = AccountExportResponse(
            user_id=user.id,
            status=user.status.value,
            display_name=user.display_name,
            created_at=user.created_at,
            memberships=memberships,
        )
        self._audit.record(
            action="account.exported",
            actor_user_id=user.id,
            target_type="user",
            target_id=user.id,
        )
        return export
