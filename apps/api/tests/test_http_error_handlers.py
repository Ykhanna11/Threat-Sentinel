import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from threat_sentinel_api import main as api_main
from threat_sentinel_api.modules.identity.service import InactiveUserError, InvalidPrincipalError
from threat_sentinel_api.modules.scans.service import ScanNotFound
from threat_sentinel_api.modules.tenants.service import (
    ActiveUserRequired,
    OrganizationPermissionDenied,
    OrganizationScopeUnavailable,
)

GENERIC_ERROR = {
    "error": {
        "code": "http_error",
        "message": "The request could not be completed.",
    }
}


@pytest.mark.parametrize(
    ("exception", "status_code", "challenge"),
    [
        (ScanNotFound("private scan and tenant identifier"), 404, None),
        (OrganizationScopeUnavailable("private organization and membership state"), 404, None),
        (OrganizationPermissionDenied("private local role and permission"), 403, None),
        (InvalidPrincipalError("private identity mapping"), 401, "Bearer"),
        (InactiveUserError("private local user status"), 401, "Bearer"),
        (ActiveUserRequired("private account state"), 401, "Bearer"),
        (
            HTTPException(
                status_code=401,
                detail="private authentication detail",
                headers={"WWW-Authenticate": "Bearer"},
            ),
            401,
            "Bearer",
        ),
    ],
)
def test_registered_application_handlers_return_generic_domain_errors(
    exception: Exception,
    status_code: int,
    challenge: str | None,
) -> None:
    app = FastAPI()
    app.exception_handlers.update(api_main.app.exception_handlers)

    @app.get("/error")
    def raise_domain_error() -> None:
        raise exception

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/error")

    assert response.status_code == status_code
    assert response.json() == GENERIC_ERROR
    assert response.headers.get("www-authenticate") == challenge
    for private_value in (
        "private",
        "scan",
        "tenant",
        "organization",
        "membership",
        "permission",
        "mapping",
        "account",
        "credential",
    ):
        assert private_value not in response.text


def test_registered_unexpected_error_handler_does_not_expose_exception_details() -> None:
    app = FastAPI()
    app.exception_handlers.update(api_main.app.exception_handlers)

    @app.get("/error")
    def raise_internal_error() -> None:
        raise RuntimeError("private database and tenant identifier")

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/error")

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "internal_server_error",
            "message": "An unexpected error occurred.",
        }
    }
    assert "private" not in response.text
    assert "database" not in response.text
    assert "tenant" not in response.text
