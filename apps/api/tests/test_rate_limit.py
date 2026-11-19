from datetime import UTC, datetime, timedelta

from fastapi import Request

from threat_sentinel_api.core.rate_limit import InProcessSensitiveEndpointRateLimiter


def _request(path: str, method: str = "POST", client: str = "192.0.2.10") -> Request:
    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "client": (client, 12345),
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )


def test_sensitive_limit_expires_and_bypass_paths_are_not_limited() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    limiter = InProcessSensitiveEndpointRateLimiter(2, 60, now=lambda: now)
    path = "/api/v1/organizations/123/archive"

    assert limiter.check(_request(path)) is None
    assert limiter.check(_request(path)) is None
    assert limiter.check(_request(path)) is not None
    assert limiter.check(_request("/api/v1/organizations/123/members")) is None
    assert limiter.check(_request("/api/v1/health", "GET")) is None

    now = now + timedelta(seconds=61)
    assert limiter.check(_request(path)) is None


def test_rate_limit_key_isolated_by_client_and_is_bounded() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    limiter = InProcessSensitiveEndpointRateLimiter(1, 60, max_keys=2, now=lambda: now)

    assert limiter.check(_request("/api/v1/account/deactivate", "POST", "one")) is None
    assert limiter.check(_request("/api/v1/account/deactivate", "POST", "one")) is not None
    assert limiter.check(_request("/api/v1/account/deactivate", "POST", "two")) is None
    assert limiter.check(_request("/api/v1/account/export", "GET", "three")) is None
    assert len(limiter._windows) <= 2


def test_sensitive_route_matching_does_not_bypass_by_suffix_or_case() -> None:
    limiter = InProcessSensitiveEndpointRateLimiter(1, 60)

    assert limiter.check(_request("/api/v1/account/deactivate", "POST")) is None
    assert limiter.check(_request("/api/v1/account/deactivate", "POST")) is not None
    assert limiter.check(_request("/api/v1/account/deactivate-extra", "POST")) is None
    assert limiter.check(_request("/api/v1/account/export", "POST")) is None
    assert limiter.check(_request("/api/v1/account/export", "GET")) is None


def test_audit_event_reads_share_client_limit_across_organizations() -> None:
    limiter = InProcessSensitiveEndpointRateLimiter(1, 60)
    first_organization_read = _request(
        "/api/v1/organizations/11111111-1111-1111-1111-111111111111/audit-events",
        "GET",
    )

    assert limiter.check(first_organization_read) is None
    limited = limiter.check(
        _request("/api/v1/organizations/22222222-2222-2222-2222-222222222222/audit-events", "GET")
    )

    assert limited is not None
    assert limited.status_code == 429
    assert len(limiter._windows) == 1


def test_forwarding_headers_do_not_replace_request_client_identity() -> None:
    limiter = InProcessSensitiveEndpointRateLimiter(1, 60)
    request = _request("/api/v1/account/deactivate", "POST", "198.51.100.10")
    request.scope["headers"] = [
        (b"x-forwarded-for", b"203.0.113.1"),
        (b"forwarded", b"for=192.0.2.200"),
    ]

    assert limiter.check(request) is None
    second = _request("/api/v1/account/deactivate", "POST", "198.51.100.10")
    second.scope["headers"] = [(b"x-forwarded-for", b"203.0.113.2")]
    assert limiter.check(second) is not None
