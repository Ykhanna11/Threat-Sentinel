from fastapi import APIRouter, Response
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from threat_sentinel_api.core.config import get_settings
from threat_sentinel_api.core.logging import get_logger
from threat_sentinel_api.db.session import get_engine

router = APIRouter()
logger = get_logger(__name__)


@router.get("/health", summary="Check API liveness")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready", summary="Check API readiness and configured dependencies")
def readiness(response: Response) -> dict[str, object]:
    settings = get_settings()
    database_url = settings.database_url
    authentication_configuration = (
        "configured" if settings.authentication_configured else "not_configured"
    )
    if database_url is None:
        return {
            "status": "ready",
            "dependencies": {
                "database": "not_configured",
                "authentication_configuration": authentication_configuration,
            },
        }

    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        logger.warning(
            "database_readiness_failed",
            extra={"failure_type": type(exc).__name__},
        )
        response.status_code = 503
        return {
            "status": "not_ready",
            "dependencies": {
                "database": "unavailable",
                "authentication_configuration": authentication_configuration,
            },
        }

    return {
        "status": "ready",
        "dependencies": {
            "database": "available",
            "authentication_configuration": authentication_configuration,
        },
    }
