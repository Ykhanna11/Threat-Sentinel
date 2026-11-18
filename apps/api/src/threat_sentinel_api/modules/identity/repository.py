from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_sentinel_api.db.authorization_locks import lock_user_for_share
from threat_sentinel_api.modules.identity.models import ExternalIdentity, User


class IdentityRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_issuer_subject(self, issuer: str, subject: str) -> ExternalIdentity | None:
        statement = select(ExternalIdentity).where(
            ExternalIdentity.issuer == issuer,
            ExternalIdentity.subject == subject,
        )
        return self._session.scalar(statement)

    def find_identity_link(self, issuer: str, subject: str) -> tuple[UUID, UUID] | None:
        statement = select(ExternalIdentity.id, ExternalIdentity.user_id).where(
            ExternalIdentity.issuer == issuer,
            ExternalIdentity.subject == subject,
        )
        link = self._session.execute(statement).one_or_none()
        if link is None:
            return None
        return link[0], link[1]

    def lock_user_for_identity_share(
        self,
        issuer: str,
        subject: str,
    ) -> tuple[UUID, User] | None:
        link = self.find_identity_link(issuer, subject)
        if link is None:
            return None

        identity_id, user_id = link
        user = lock_user_for_share(self._session, user_id)
        if user is None or self.find_identity_link(issuer, subject) != link:
            return None
        return identity_id, user

    def lock_user_for_organization_creation(
        self,
        issuer: str,
        subject: str,
    ) -> User | None:
        link = self.find_identity_link(issuer, subject)
        if link is None:
            return None

        _, user_id = link
        user = lock_user_for_share(self._session, user_id)
        if user is None:
            return None
        if self.find_identity_link(issuer, subject) != link:
            return None
        return user

    def add(self, identity: ExternalIdentity) -> None:
        self._session.add(identity)
        self._session.flush()
