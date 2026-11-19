from collections import deque
from datetime import UTC, datetime
from collections.abc import Callable
import re
from threading import Lock
from fastapi import Request
from fastapi.responses import JSONResponse


class InProcessSensitiveEndpointRateLimiter:
    """Best-effort local limit; distributed deployments require a shared store."""

    def __init__(
        self,
        requests: int,
        window_seconds: int,
        *,
        max_keys: int = 4096,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._requests = requests
        self._window_seconds = window_seconds
        self._max_keys = max_keys
        self._windows: dict[tuple[str, str], deque[datetime]] = {}
        self._lock = Lock()
        self._now = now or (lambda: datetime.now(UTC))

    def _is_sensitive(self, request: Request) -> bool:
        path = request.url.path
        if request.method == "GET":
            return (
                path == "/api/v1/account/export"
                or re.fullmatch(
                    r"/api/v1/organizations/[0-9A-Fa-f-]+/audit-events",
                    path,
                )
                is not None
            )
        if request.method == "POST" and path == "/api/v1/account/deactivate":
            return True
        if request.method == "POST" and path == "/api/v1/organization-invitations/accept":
            return True
        if re.fullmatch(
            r"/api/v1/organizations/[0-9A-Fa-f-]+/(?:suspend|reactivate|archive|restore)",
            path,
        ):
            return request.method == "POST"
        if re.fullmatch(
            r"/api/v1/organizations/[0-9A-Fa-f-]+/ownership-transfer",
            path,
        ):
            return request.method == "POST"
        if re.fullmatch(
            r"/api/v1/organizations/[0-9A-Fa-f-]+/invitations(?:/[0-9A-Fa-f-]+)?",
            path,
        ):
            return request.method in {"POST", "DELETE"}
        if re.fullmatch(
            r"/api/v1/organizations/[0-9A-Fa-f-]+/members/[0-9A-Fa-f-]+",
            path,
        ):
            return request.method in {"PATCH", "DELETE"}
        return False

    def check(self, request: Request) -> JSONResponse | None:
        if not self._is_sensitive(request):
            return None

        now = self._now()
        client = request.client.host if request.client is not None else "unknown"
        path = request.url.path.rstrip("/") or "/"
        if request.method == "GET" and re.fullmatch(
            r"/api/v1/organizations/[0-9A-Fa-f-]+/audit-events",
            path,
        ):
            path = "/api/v1/organizations/{organization_id}/audit-events"
        key = (client, path)
        with self._lock:
            cutoff = now.timestamp() - self._window_seconds
            expired_keys = [
                stored_key
                for stored_key, timestamps in self._windows.items()
                if not timestamps or timestamps[-1].timestamp() <= cutoff
            ]
            for stored_key in expired_keys:
                del self._windows[stored_key]
            if key not in self._windows and len(self._windows) >= self._max_keys:
                oldest = min(
                    self._windows,
                    key=lambda stored_key: (
                        self._windows[stored_key][0].timestamp() if self._windows[stored_key] else 0
                    ),
                )
                del self._windows[oldest]
            window = self._windows.setdefault(key, deque())
            while window and window[0].timestamp() <= cutoff:
                window.popleft()
            if key not in self._windows:
                raise RuntimeError("rate-limit key setup failed")
            if len(window) >= self._requests:
                if len(self._windows) > self._max_keys:
                    oldest = min(
                        self._windows,
                        key=lambda stored_key: (
                            self._windows[stored_key][-1].timestamp()
                            if self._windows[stored_key]
                            else 0
                        ),
                    )
                    del self._windows[oldest]
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "code": "rate_limited",
                            "message": "The request could not be completed.",
                        }
                    },
                )
            window.append(now)
            if len(self._windows) > self._max_keys:
                oldest = min(
                    self._windows,
                    key=lambda stored_key: (
                        self._windows[stored_key][-1].timestamp()
                        if self._windows[stored_key]
                        else 0
                    ),
                )
                del self._windows[oldest]
        return None
