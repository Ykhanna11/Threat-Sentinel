from uuid import UUID

from sqlalchemy.orm import Session

from threat_sentinel_api.db.session import SessionFactory, unit_of_work
from threat_sentinel_api.modules.audit.recording import record_failure_event
from threat_sentinel_api.modules.identity.enums import UserStatus
from threat_sentinel_api.modules.identity.repository import IdentityRepository
from threat_sentinel_api.modules.identity.schemas import AuthenticatedPrincipal
from threat_sentinel_api.modules.identity.service import InactiveUserError
from threat_sentinel_api.modules.scans.models import SecurityScan
from threat_sentinel_api.modules.scans.repository import ScanRepository
from threat_sentinel_api.modules.tenants.authorization import (
    OrganizationScanAction,
    allows_organization_scan_action,
)
from threat_sentinel_api.modules.tenants.repository import OrganizationRepository
from threat_sentinel_api.modules.tenants.service import (
    OrganizationAccessDenied,
    OrganizationPermissionDenied,
    OrganizationService,
)


class ScanNotFound(LookupError):
    """Raised when a scan is absent from the caller's authorized scope."""


class ScanService:
    """Keep authorization locks and scan access in one unit of work."""

    def __init__(self, session_factory: SessionFactory | None = None) -> None:
        self._session_factory = session_factory

    def create_personal_scan(self, principal: AuthenticatedPrincipal) -> SecurityScan:
        with unit_of_work(self._session_factory) as session:
            self._require_active_user(session, principal)
            scan = SecurityScan(
                owner_user_id=principal.user_id,
                created_by_user_id=principal.user_id,
            )
            ScanRepository(session).add(scan)
            return scan

    def list_personal_scans(self, principal: AuthenticatedPrincipal) -> list[SecurityScan]:
        with unit_of_work(self._session_factory) as session:
            self._require_active_user(session, principal)
            return ScanRepository(session).list_personal_for_owner(principal.user_id)

    def get_personal_scan(
        self,
        principal: AuthenticatedPrincipal,
        scan_id: UUID,
    ) -> SecurityScan:
        with unit_of_work(self._session_factory) as session:
            self._require_active_user(session, principal)
            scan = ScanRepository(session).find_personal_by_id(scan_id, principal.user_id)
            if scan is None:
                raise ScanNotFound("The scan was not found.")
            return scan

    def create_organization_scan(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
    ) -> SecurityScan:
        try:
            with unit_of_work(self._session_factory) as session:
                self._require_organization_action(
                    session,
                    principal,
                    organization_id,
                    OrganizationScanAction.CREATE,
                )
                scan = SecurityScan(
                    organization_id=organization_id,
                    created_by_user_id=principal.user_id,
                )
                ScanRepository(session).add(scan)
                return scan
        except (InactiveUserError, OrganizationAccessDenied) as error:
            self._record_organization_denial(
                principal,
                organization_id,
                "organization.scan.create_denied",
                self._organization_denial_reason(error),
            )
            raise

    def list_organization_scans(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
    ) -> list[SecurityScan]:
        try:
            with unit_of_work(self._session_factory) as session:
                self._require_organization_action(
                    session,
                    principal,
                    organization_id,
                    OrganizationScanAction.LIST,
                )
                return ScanRepository(session).list_organization_for(organization_id)
        except (InactiveUserError, OrganizationAccessDenied) as error:
            self._record_organization_denial(
                principal,
                organization_id,
                "organization.scan.list_denied",
                self._organization_denial_reason(error),
            )
            raise

    def get_organization_scan(
        self,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        scan_id: UUID,
    ) -> SecurityScan:
        try:
            with unit_of_work(self._session_factory) as session:
                self._require_organization_action(
                    session,
                    principal,
                    organization_id,
                    OrganizationScanAction.READ,
                )
                scan = ScanRepository(session).find_organization_by_id(scan_id, organization_id)
                if scan is None:
                    raise ScanNotFound("The scan was not found.")
                return scan
        except (InactiveUserError, OrganizationAccessDenied, ScanNotFound) as error:
            self._record_organization_denial(
                principal,
                organization_id,
                "organization.scan.read_denied",
                (
                    "resource_unavailable"
                    if isinstance(error, ScanNotFound)
                    else self._organization_denial_reason(error)
                ),
            )
            raise

    @staticmethod
    def _require_active_user(session: Session, principal: AuthenticatedPrincipal) -> None:
        locked_identity = IdentityRepository(session).lock_user_for_identity_share(
            principal.issuer,
            principal.subject,
        )
        if locked_identity is None:
            raise InactiveUserError("The linked account is not active.")
        identity_id, user = locked_identity
        if (
            identity_id != principal.external_identity_id
            or user.id != principal.user_id
            or user.status is not UserStatus.ACTIVE
        ):
            raise InactiveUserError("The linked account is not active.")

    @staticmethod
    def _require_organization_action(
        session: Session,
        principal: AuthenticatedPrincipal,
        organization_id: UUID,
        action: OrganizationScanAction,
    ) -> None:
        membership = OrganizationService(OrganizationRepository(session)).require_active_membership(
            principal,
            organization_id,
        )
        if not allows_organization_scan_action(membership.role, action):
            raise OrganizationPermissionDenied(
                "The user is not authorized for this organization scan action."
            )

    def _record_organization_denial(
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
    def _organization_denial_reason(error: Exception) -> str:
        if isinstance(error, OrganizationPermissionDenied):
            return "insufficient_role"
        if isinstance(error, InactiveUserError):
            return "inactive_account"
        return "scope_unavailable"
