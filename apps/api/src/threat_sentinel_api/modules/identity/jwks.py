import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

import jwt

from threat_sentinel_api.core.config import JwtSigningAlgorithm, Settings
from threat_sentinel_api.modules.identity.auth_errors import (
    InvalidAccessToken,
    TrustedKeySourceUnavailable,
)

MAX_JWKS_RESPONSE_BYTES = 64 * 1024
JWKS_CONNECT_TIMEOUT_SECONDS = 3.0
JWKS_READ_TIMEOUT_SECONDS = 3.0
UNKNOWN_KID_REFRESH_INTERVAL_SECONDS = 30.0
MIN_JWKS_REFRESH_INTERVAL_SECONDS = 5.0

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Sequence[IpAddress]]

_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_ALGORITHM_KEY_TYPES: dict[str, tuple[str, str | None]] = {
    "RS256": ("RSA", None),
    "RS384": ("RSA", None),
    "RS512": ("RSA", None),
    "PS256": ("RSA", None),
    "PS384": ("RSA", None),
    "PS512": ("RSA", None),
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
    "ES512": ("EC", "P-521"),
    "EdDSA": ("OKP", None),
}


@dataclass(frozen=True)
class JwksHttpResponse:
    status_code: int
    body: bytes
    content_encoding: str | None = None


class JwksTransport(Protocol):
    def get(
        self,
        url: str,
        addresses: Sequence[IpAddress],
        timeout: float,
        max_bytes: int,
    ) -> JwksHttpResponse: ...


def _resolve_addresses(host: str, port: int) -> Sequence[IpAddress]:
    try:
        results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.") from exc

    addresses: list[IpAddress] = []
    for family, _, _, _, sockaddr in results:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
        address = ipaddress.ip_address(sockaddr[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        if _is_prohibited_address(address):
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
    return addresses


def _is_prohibited_address(address: IpAddress) -> bool:
    return (
        not address.is_global
        or address.is_reserved
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_unspecified
    )


class _PinnedHttpsConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        hostname: str,
        port: int,
        address: IpAddress,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(hostname, port, timeout=timeout, context=context)
        self._resolved_address = address
        self._tls_context = context

    def connect(self) -> None:
        family = socket.AF_INET6 if self._resolved_address.version == 6 else socket.AF_INET
        raw_socket = socket.socket(family, socket.SOCK_STREAM)
        try:
            raw_socket.settimeout(self.timeout)
            if family == socket.AF_INET6:
                raw_socket.connect((str(self._resolved_address), self.port, 0, 0))
            else:
                raw_socket.connect((str(self._resolved_address), self.port))
            self.sock = self._tls_context.wrap_socket(raw_socket, server_hostname=self.host)
        except Exception:
            raw_socket.close()
            raise


class PinnedHttpsTransport:
    """Fetch one HTTPS resource over a previously validated, pinned public IP."""

    def get(
        self,
        url: str,
        addresses: Sequence[IpAddress],
        timeout: float,
        max_bytes: int,
    ) -> JwksHttpResponse:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or not addresses
            or any(_is_prohibited_address(address) for address in addresses)
        ):
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")

        port = parsed.port or 443
        path = parsed.path or "/"
        host_header = parsed.hostname
        if ":" in host_header:
            host_header = f"[{host_header}]"
        if port != 443:
            host_header = f"{host_header}:{port}"

        connection = _PinnedHttpsConnection(
            parsed.hostname,
            port,
            addresses[0],
            timeout,
            ssl.create_default_context(),
        )
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "Host": host_header,
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            content_encoding = response.getheader("Content-Encoding")
            content_length = response.getheader("Content-Length")
            if content_encoding not in (None, "", "identity"):
                raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError as exc:
                    raise TrustedKeySourceUnavailable(
                        "Trusted signing keys are unavailable."
                    ) from exc
                if declared_size < 0 or declared_size > max_bytes:
                    raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
            return JwksHttpResponse(response.status, body, content_encoding)
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.") from exc
        finally:
            connection.close()


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member.")
        result[key] = value
    return result


def _parse_jwks(
    body: bytes,
    algorithms: Sequence[JwtSigningAlgorithm],
    max_entries: int,
) -> dict[str, dict[str, jwt.PyJWK]]:
    try:
        document = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Invalid JSON number.")),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.") from exc

    if (
        not isinstance(document, dict)
        or set(document) != {"keys"}
        or not isinstance(document["keys"], list)
        or not document["keys"]
        or len(document["keys"]) > max_entries
    ):
        raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")

    parsed_keys: dict[str, dict[str, jwt.PyJWK]] = {}
    seen_kids: set[str] = set()
    for key_data in document["keys"]:
        if not isinstance(key_data, dict) or _PRIVATE_JWK_MEMBERS.intersection(key_data):
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
        kid = key_data.get("kid")
        if not isinstance(kid, str) or not kid.strip() or len(kid) > 256 or kid in seen_kids:
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
        seen_kids.add(kid)

        use = key_data.get("use")
        if use is not None and use != "sig":
            continue
        key_ops = key_data.get("key_ops")
        if key_ops is not None and (
            not isinstance(key_ops, list)
            or any(not isinstance(operation, str) for operation in key_ops)
            or key_ops != ["verify"]
            or len(set(key_ops)) != len(key_ops)
        ):
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")

        key_type = key_data.get("kty")
        curve = key_data.get("crv")
        key_algorithm = key_data.get("alg")
        if key_type not in ("RSA", "EC", "OKP"):
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
        if key_type == "RSA":
            modulus = key_data.get("n")
            exponent = key_data.get("e")
            if (
                not isinstance(modulus, str)
                or not isinstance(exponent, str)
                or not 342 <= len(modulus) <= 1366
                or not 1 <= len(exponent) <= 16
            ):
                raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
        if key_type == "OKP" and curve not in ("Ed25519", "Ed448"):
            continue
        if key_algorithm is not None and (
            not isinstance(key_algorithm, str) or key_algorithm not in algorithms
        ):
            continue

        compatible_algorithms = [
            algorithm
            for algorithm in algorithms
            if _ALGORITHM_KEY_TYPES[algorithm][0] == key_type
            and (
                _ALGORITHM_KEY_TYPES[algorithm][1] is None
                or _ALGORITHM_KEY_TYPES[algorithm][1] == curve
            )
            and (key_algorithm is None or key_algorithm == algorithm)
        ]
        if not compatible_algorithms:
            continue

        key_algorithms: dict[str, jwt.PyJWK] = {}
        try:
            for algorithm in compatible_algorithms:
                key_algorithms[algorithm] = jwt.PyJWK.from_dict(
                    key_data,
                    algorithm=algorithm,
                )
        except (jwt.PyJWTError, TypeError, ValueError) as exc:
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.") from exc
        if any(
            algorithm.startswith(("RS", "PS")) and not 2048 <= key.key.key_size <= 8192
            for algorithm, key in key_algorithms.items()
        ):
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
        if key_algorithms:
            parsed_keys[kid] = key_algorithms

    return parsed_keys


class TrustedJwksKeyStore:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: JwksTransport | None = None,
        resolver: Resolver = _resolve_addresses,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if settings.auth_trusted_jwks_url is None or settings.auth_allowed_jwt_algorithms is None:
            raise ValueError("Complete authentication configuration is required.")
        self._url = settings.auth_trusted_jwks_url
        self._algorithms = tuple(settings.auth_allowed_jwt_algorithms)
        self._ttl = settings.auth_jwks_cache_ttl_seconds
        self._max_entries = settings.auth_jwks_cache_max_entries
        self._transport = transport or PinnedHttpsTransport()
        self._resolver = resolver
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, dict[str, jwt.PyJWK]] = {}
        self._expires_at = 0.0
        self._last_attempt_at = float("-inf")

    def get_key(self, kid: str, algorithm: str) -> jwt.PyJWK:
        now = self._clock()
        with self._lock:
            fresh = now < self._expires_at
            if not fresh:
                if now - self._last_attempt_at < MIN_JWKS_REFRESH_INTERVAL_SECONDS:
                    raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
                self._refresh(now)

            key = self._keys.get(kid, {}).get(algorithm)
            if key is not None:
                return key

            if now - self._last_attempt_at < UNKNOWN_KID_REFRESH_INTERVAL_SECONDS:
                raise InvalidAccessToken("Invalid access token.")
            self._refresh(now)
            key = self._keys.get(kid, {}).get(algorithm)
            if key is None:
                raise InvalidAccessToken("Invalid access token.")
            return key

    def _refresh(self, now: float) -> None:
        self._last_attempt_at = now
        parsed = urlsplit(self._url)
        if parsed.hostname is None:
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
        try:
            addresses = self._resolver(parsed.hostname, parsed.port or 443)
        except TrustedKeySourceUnavailable:
            raise
        except OSError as exc:
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.") from exc
        if not addresses or any(_is_prohibited_address(address) for address in addresses):
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")

        try:
            response = self._transport.get(
                self._url,
                addresses,
                JWKS_CONNECT_TIMEOUT_SECONDS,
                MAX_JWKS_RESPONSE_BYTES,
            )
        except TrustedKeySourceUnavailable:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.") from exc
        if (
            response.status_code != 200
            or len(response.body) > MAX_JWKS_RESPONSE_BYTES
            or response.content_encoding not in (None, "", "identity")
        ):
            raise TrustedKeySourceUnavailable("Trusted signing keys are unavailable.")
        self._keys = _parse_jwks(
            response.body,
            self._algorithms,
            self._max_entries,
        )
        self._expires_at = now + self._ttl
