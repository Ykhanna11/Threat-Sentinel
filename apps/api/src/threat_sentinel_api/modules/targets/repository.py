from datetime import UTC, datetime, timedelta
from hashlib import sha256
import secrets
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from threat_sentinel_api.modules.targets.models import SecurityTarget, TargetVerificationChallenge

TARGET_CHALLENGE_TTL = timedelta(hours=1)


class TargetRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_id(
        self,
        target_id: UUID,
        organization_id: UUID,
        *,
        for_update: bool = False,
    ) -> SecurityTarget | None:
        statement = select(SecurityTarget).where(
            SecurityTarget.id == target_id,
            SecurityTarget.organization_id == organization_id,
        )
        if for_update:
            statement = statement.with_for_update()
        return self._session.scalar(statement)

    def find_by_hostname(
        self,
        organization_id: UUID,
        hostname: str,
    ) -> SecurityTarget | None:
        return self._session.scalar(
            select(SecurityTarget).where(
                SecurityTarget.organization_id == organization_id,
                SecurityTarget.hostname == hostname,
            )
        )

    def find_active_challenge(
        self,
        organization_id: UUID,
        target_id: UUID,
        *,
        now: datetime | None = None,
    ) -> TargetVerificationChallenge | None:
        current_time = now or datetime.now(UTC)
        return self._session.scalar(
            select(TargetVerificationChallenge).where(
                TargetVerificationChallenge.organization_id == organization_id,
                TargetVerificationChallenge.target_id == target_id,
                TargetVerificationChallenge.expires_at > current_time,
            )
        )

    def add_target(
        self,
        organization_id: UUID,
        hostname: str,
        created_by_user_id: UUID,
    ) -> SecurityTarget:
        target = SecurityTarget(
            organization_id=organization_id,
            hostname=hostname,
            created_by_user_id=created_by_user_id,
        )
        self._session.add(target)
        self._session.flush()
        return target

    def issue_challenge(
        self,
        target: SecurityTarget,
        issued_by_user_id: UUID,
        *,
        now: datetime | None = None,
    ) -> tuple[TargetVerificationChallenge, str]:
        issued_at = now or datetime.now(UTC)
        prior = self._session.scalar(
            select(TargetVerificationChallenge)
            .where(
                TargetVerificationChallenge.organization_id == target.organization_id,
                TargetVerificationChallenge.target_id == target.id,
            )
            .with_for_update()
        )
        while True:
            challenge_value = secrets.token_urlsafe(32)
            challenge_hash = sha256(challenge_value.encode("ascii")).hexdigest()
            if prior is None or prior.challenge_hash != challenge_hash:
                break

        if prior is None:
            prior = TargetVerificationChallenge(
                organization_id=target.organization_id,
                target_id=target.id,
                issued_by_user_id=issued_by_user_id,
                challenge_hash=challenge_hash,
                created_at=issued_at,
                expires_at=issued_at + TARGET_CHALLENGE_TTL,
            )
            self._session.add(prior)
        else:
            prior.issued_by_user_id = issued_by_user_id
            prior.challenge_hash = challenge_hash
            prior.created_at = issued_at
            prior.expires_at = issued_at + TARGET_CHALLENGE_TTL
        self._session.flush()
        return prior, challenge_value

    def revoke_challenge(
        self,
        organization_id: UUID,
        target_id: UUID,
        challenge_id: UUID,
    ) -> bool:
        result = self._session.execute(
            delete(TargetVerificationChallenge)
            .where(
                TargetVerificationChallenge.id == challenge_id,
                TargetVerificationChallenge.organization_id == organization_id,
                TargetVerificationChallenge.target_id == target_id,
            )
            .returning(TargetVerificationChallenge.id)
        )
        return result.scalar_one_or_none() is not None

    def verify_target_after_dns_proof(
        self,
        target: SecurityTarget,
        organization_id: UUID,
        challenge_id: UUID,
        challenge_hash: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        """Atomically consume the challenge snapshot and mark its locked target verified."""
        verified_at = now or datetime.now(UTC)
        result = self._session.execute(
            delete(TargetVerificationChallenge)
            .where(
                TargetVerificationChallenge.id == challenge_id,
                TargetVerificationChallenge.organization_id == organization_id,
                TargetVerificationChallenge.target_id == target.id,
                TargetVerificationChallenge.challenge_hash == challenge_hash,
                TargetVerificationChallenge.expires_at > verified_at,
            )
            .returning(TargetVerificationChallenge.id)
        )
        if result.scalar_one_or_none() is None:
            return False
        target.verified_at = verified_at
        self._session.flush()
        return True
