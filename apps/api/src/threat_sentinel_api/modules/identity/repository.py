from sqlalchemy import select
from sqlalchemy.orm import Session

from threat_sentinel_api.modules.identity.models import ExternalIdentity


class IdentityRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def find_by_issuer_subject(self, issuer: str, subject: str) -> ExternalIdentity | None:
        statement = select(ExternalIdentity).where(
            ExternalIdentity.issuer == issuer,
            ExternalIdentity.subject == subject,
        )
        return self._session.scalar(statement)

    def add(self, identity: ExternalIdentity) -> None:
        self._session.add(identity)
        self._session.flush()
