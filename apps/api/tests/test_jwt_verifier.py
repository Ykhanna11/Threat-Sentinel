import asyncio
import base64
import ipaddress
import json
import secrets
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import SecretStr

from threat_sentinel_api.core.config import Settings
from threat_sentinel_api.modules.identity.auth_errors import (
    AuthenticationVerifierFailure,
    InvalidAccessToken,
    TrustedKeySourceUnavailable,
)
from threat_sentinel_api.modules.identity.jwt_verifier import JwtAccessTokenVerifier
from threat_sentinel_api.modules.identity.jwks import (
    MAX_JWKS_RESPONSE_BYTES,
    JwksHttpResponse,
    PinnedHttpsTransport,
    TrustedJwksKeyStore,
    _PinnedHttpsConnection,
)
from threat_sentinel_api.modules.identity.schemas import VerifiedAccessTokenClaims


def _b64url(value: int) -> str:
    byte_length = (value.bit_length() + 7) // 8
    encoded = base64.urlsafe_b64encode(value.to_bytes(byte_length, "big"))
    return encoded.rstrip(b"=").decode("ascii")


def _rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _rsa_jwk(private_key: rsa.RSAPrivateKey, kid: str = "key-1") -> dict[str, str]:
    public_numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url(public_numbers.n),
        "e": _b64url(public_numbers.e),
    }


def _settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "auth_expected_issuer": "https://issuer.example/",
        "auth_expected_audience": "threat-sentinel-api",
        "auth_trusted_jwks_url": "https://keys.example/jwks",
        "auth_allowed_jwt_algorithms": ["RS256"],
        "auth_clock_skew_seconds": 0,
        "auth_jwks_cache_ttl_seconds": 300,
        "auth_jwks_cache_max_entries": 16,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


class FakeTransport:
    def __init__(
        self,
        response: JwksHttpResponse | Exception | list[JwksHttpResponse | Exception],
    ) -> None:
        self.responses = response if isinstance(response, list) else [response]
        self.calls: list[tuple[str, tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]]] = []

    def get(
        self,
        url: str,
        addresses: Any,
        timeout: float,
        max_bytes: int,
    ) -> JwksHttpResponse:
        assert timeout > 0
        assert max_bytes == MAX_JWKS_RESPONSE_BYTES
        self.calls.append((url, tuple(addresses)))
        response = self.responses[min(len(self.calls) - 1, len(self.responses) - 1)]
        if isinstance(response, Exception):
            raise response
        return response


def _response(jwks: dict[str, object], *, status: int = 200) -> JwksHttpResponse:
    return JwksHttpResponse(status, json.dumps(jwks).encode())


def _jwks(*keys: dict[str, str]) -> dict[str, object]:
    return {"keys": list(keys)}


def _public_resolver(
    _host: str,
    _port: int,
) -> list[ipaddress.IPv4Address]:
    return [ipaddress.ip_address("93.184.216.34")]


def _verifier(
    private_key: rsa.RSAPrivateKey | None = None,
    *,
    settings: Settings | None = None,
    response: JwksHttpResponse | Exception | list[JwksHttpResponse | Exception] | None = None,
    resolver: Callable[..., Any] = _public_resolver,
    cache_clock: Callable[[], float] = time.monotonic,
) -> tuple[JwtAccessTokenVerifier, FakeTransport]:
    signing_key = private_key or _rsa_key()
    transport = FakeTransport(response or _response(_jwks(_rsa_jwk(signing_key))))
    configuration = settings or _settings()
    store = TrustedJwksKeyStore(
        configuration,
        transport=transport,
        resolver=resolver,
        clock=cache_clock,
    )
    return JwtAccessTokenVerifier(configuration, key_store=store), transport


def _token(
    private_key: rsa.RSAPrivateKey,
    **overrides: object,
) -> str:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": "https://issuer.example/",
        "sub": "subject-123",
        "aud": "threat-sentinel-api",
        "iat": int((now - timedelta(seconds=5)).timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    claims.update(overrides)
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1", "typ": "at+jwt"},
    )


def _verify(verifier: JwtAccessTokenVerifier, token: str) -> VerifiedAccessTokenClaims:
    return asyncio.run(verifier.verify_bearer_token(SecretStr(token)))


def test_valid_access_token_returns_verified_minimal_claims() -> None:
    private_key = _rsa_key()
    verifier, _ = _verifier(private_key)
    token = _token(
        private_key,
        nbf=int((datetime.now(UTC) - timedelta(seconds=5)).timestamp()),
        email="user@example.test",
        email_verified=True,
    )

    claims = _verify(verifier, token)

    assert claims == VerifiedAccessTokenClaims(
        issuer="https://issuer.example/",
        subject="subject-123",
        audiences=("threat-sentinel-api",),
        issued_at=claims.issued_at,
        expires_at=claims.expires_at,
        not_before=claims.not_before,
        key_id="key-1",
        email="user@example.test",
        email_verified=True,
        token_type="at+jwt",
    )
    assert claims.issuer == "https://issuer.example/"
    assert claims.subject == "subject-123"


def test_provider_roles_and_permissions_are_not_returned_as_authorization() -> None:
    private_key = _rsa_key()
    verifier, _ = _verifier(private_key)
    token = _token(private_key, roles=["admin"], permissions=["*"])

    claims = _verify(verifier, token)

    assert not hasattr(claims, "roles")
    assert not hasattr(claims, "permissions")


def test_configured_clock_skew_is_applied_to_token_time_claims() -> None:
    private_key = _rsa_key()
    verifier, _ = _verifier(
        private_key,
        settings=_settings(auth_clock_skew_seconds=30),
    )
    now = datetime.now(UTC)

    expired_within_skew = _token(
        private_key,
        iat=int((now - timedelta(seconds=60)).timestamp()),
        exp=int((now - timedelta(seconds=5)).timestamp()),
    )
    not_yet_valid_within_skew = _token(
        private_key,
        nbf=int((now + timedelta(seconds=5)).timestamp()),
    )

    assert _verify(verifier, expired_within_skew).subject == "subject-123"
    assert _verify(verifier, not_yet_valid_within_skew).subject == "subject-123"


@pytest.mark.parametrize("algorithm", ["ES256", "EdDSA"])
def test_supported_non_rsa_algorithms_verify_only_matching_jwks_keys(algorithm: str) -> None:
    now = datetime.now(UTC)
    payload = {
        "iss": "https://issuer.example/",
        "sub": "subject-123",
        "aud": "threat-sentinel-api",
        "iat": int((now - timedelta(seconds=5)).timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }

    if algorithm == "ES256":
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_numbers = private_key.public_key().public_numbers()
        jwk = {
            "kty": "EC",
            "use": "sig",
            "alg": algorithm,
            "kid": "key-1",
            "crv": "P-256",
            "x": _b64url(public_numbers.x),
            "y": _b64url(public_numbers.y),
        }
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        jwk = {
            "kty": "OKP",
            "use": "sig",
            "alg": algorithm,
            "kid": "key-1",
            "crv": "Ed25519",
            "x": base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode(),
        }

    settings = _settings(auth_allowed_jwt_algorithms=[algorithm])
    transport = FakeTransport(_response(_jwks(jwk)))
    store = TrustedJwksKeyStore(
        settings,
        transport=transport,
        resolver=_public_resolver,
    )
    verifier = JwtAccessTokenVerifier(settings, key_store=store)
    token = jwt.encode(
        payload,
        private_key,
        algorithm=algorithm,
        headers={"kid": "key-1", "typ": "at+jwt"},
    )

    assert _verify(verifier, token).subject == "subject-123"


def test_bad_signature_is_rejected() -> None:
    trusted_key = _rsa_key()
    verifier, _ = _verifier(trusted_key)

    with pytest.raises(InvalidAccessToken):
        _verify(verifier, _token(_rsa_key()))


@pytest.mark.parametrize("token", ["", "not-a-jwt", "a.b.c", "a.b.c.d"])
def test_malformed_and_oversized_tokens_are_rejected(token: str) -> None:
    verifier, _ = _verifier()

    with pytest.raises(InvalidAccessToken):
        _verify(verifier, token)


def test_oversized_token_is_rejected() -> None:
    verifier, _ = _verifier()

    with pytest.raises(InvalidAccessToken):
        _verify(verifier, "a" * 16_385)


@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://attacker.example/"},
        {"aud": "another-api"},
        {"exp": int((datetime.now(UTC) - timedelta(minutes=1)).timestamp())},
        {"nbf": int((datetime.now(UTC) + timedelta(minutes=1)).timestamp())},
        {"sub": ""},
        {"sub": "  "},
        {"iat": True},
        {"iat": int((datetime.now(UTC) + timedelta(minutes=1)).timestamp())},
    ],
)
def test_invalid_registered_claims_are_rejected(overrides: dict[str, object]) -> None:
    private_key = _rsa_key()
    verifier, _ = _verifier(private_key)

    with pytest.raises(InvalidAccessToken):
        _verify(verifier, _token(private_key, **overrides))


@pytest.mark.parametrize(
    "claim_name",
    ["exp", "iat", "sub", "iss", "aud"],
)
def test_missing_required_claims_are_rejected(claim_name: str) -> None:
    private_key = _rsa_key()
    verifier, _ = _verifier(private_key)
    payload: dict[str, object] = {
        "iss": "https://issuer.example/",
        "sub": "subject-123",
        "aud": "threat-sentinel-api",
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
    }
    del payload[claim_name]
    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1", "typ": "at+jwt"},
    )

    with pytest.raises(InvalidAccessToken):
        _verify(verifier, token)


def test_missing_and_unknown_key_ids_are_rejected() -> None:
    private_key = _rsa_key()
    verifier, transport = _verifier(private_key)
    token_without_kid = jwt.encode(
        {
            "iss": "https://issuer.example/",
            "sub": "subject",
            "aud": "threat-sentinel-api",
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        },
        private_key,
        algorithm="RS256",
        headers={"typ": "at+jwt"},
    )
    unknown_kid = jwt.encode(
        {
            "iss": "https://issuer.example/",
            "sub": "subject",
            "aud": "threat-sentinel-api",
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "unknown", "typ": "at+jwt"},
    )

    with pytest.raises(InvalidAccessToken):
        _verify(verifier, token_without_kid)
    with pytest.raises(InvalidAccessToken):
        _verify(verifier, unknown_kid)
    assert len(transport.calls) == 1


def test_disallowed_algorithms_and_untrusted_key_headers_are_rejected() -> None:
    private_key = _rsa_key()
    verifier, _ = _verifier(private_key)
    payload = {
        "iss": "https://issuer.example/",
        "sub": "subject",
        "aud": "threat-sentinel-api",
        "iat": int(datetime.now(UTC).timestamp()),
        "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
    }
    none_token = jwt.encode(payload, key=None, algorithm="none", headers={"typ": "at+jwt"})
    hmac_token = jwt.encode(
        payload,
        secrets.token_bytes(32),
        algorithm="HS256",
        headers={"kid": "key-1", "typ": "at+jwt"},
    )
    jku_token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1", "typ": "at+jwt", "jku": "https://attacker/keys"},
    )

    with pytest.raises(InvalidAccessToken):
        _verify(verifier, none_token)
    with pytest.raises(InvalidAccessToken):
        _verify(verifier, hmac_token)
    with pytest.raises(InvalidAccessToken):
        _verify(verifier, jku_token)


@pytest.mark.parametrize("token_type", ["JWT", "id+jwt", None])
def test_non_access_token_types_are_rejected(token_type: str | None) -> None:
    private_key = _rsa_key()
    verifier, _ = _verifier(private_key)
    headers: dict[str, object] = {"kid": "key-1"}
    if token_type is not None:
        headers["typ"] = token_type
    token = jwt.encode(
        {
            "iss": "https://issuer.example/",
            "sub": "subject",
            "aud": "threat-sentinel-api",
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        },
        private_key,
        algorithm="RS256",
        headers=headers,
    )

    with pytest.raises(InvalidAccessToken):
        _verify(verifier, token)


@pytest.mark.parametrize(
    "jwks",
    [
        b"not-json",
        b'{"keys":[]}',
        b'{"keys":[{"kid":"dup","kty":"RSA","n":"x","e":"AQAB"},{"kid":"dup","kty":"RSA","n":"x","e":"AQAB"}]}',
        b'{"keys":[{"kid":"key-1","kty":"RSA","n":"x","e":"AQAB","d":"private"}]}',
    ],
)
def test_malformed_or_private_jwks_are_rejected(jwks: bytes) -> None:
    verifier, _ = _verifier(response=JwksHttpResponse(200, jwks))

    with pytest.raises(TrustedKeySourceUnavailable):
        _verify(verifier, _token(_rsa_key()))


@pytest.mark.parametrize(
    "response",
    [
        JwksHttpResponse(302, b"", None),
        JwksHttpResponse(200, b"{}", "gzip"),
        JwksHttpResponse(200, b"x" * (MAX_JWKS_RESPONSE_BYTES + 1)),
        TimeoutError("read timed out"),
    ],
)
def test_untrusted_redirect_timeout_and_oversize_response_fail_closed(
    response: JwksHttpResponse | Exception,
) -> None:
    verifier, _ = _verifier(response=response)

    with pytest.raises(TrustedKeySourceUnavailable):
        _verify(verifier, _token(_rsa_key()))


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.10",
        "169.254.169.254",
        "224.0.0.1",
        "::1",
        "fc00::1",
    ],
)
def test_private_and_reserved_dns_answers_are_rejected_without_transport(
    address: str,
) -> None:
    transport = FakeTransport(_response(_jwks(_rsa_jwk(_rsa_key()))))
    store = TrustedJwksKeyStore(
        _settings(),
        transport=transport,
        resolver=lambda _host, _port: [ipaddress.ip_address(address)],
    )

    with pytest.raises(TrustedKeySourceUnavailable):
        store.get_key("key-1", "RS256")
    assert not transport.calls


def test_cache_reuses_keys_and_throttles_unknown_key_refreshes() -> None:
    private_key = _rsa_key()
    clock_values = [100.0]
    verifier, transport = _verifier(
        private_key,
        cache_clock=lambda: clock_values[0],
    )
    token = _token(private_key)

    _verify(verifier, token)
    _verify(verifier, token)
    assert len(transport.calls) == 1
    assert transport.calls[0][1] == (ipaddress.ip_address("93.184.216.34"),)

    token_unknown = jwt.encode(
        {
            "iss": "https://issuer.example/",
            "sub": "subject",
            "aud": "threat-sentinel-api",
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "rotated", "typ": "at+jwt"},
    )
    for _ in range(2):
        with pytest.raises(InvalidAccessToken):
            _verify(verifier, token_unknown)
    assert len(transport.calls) == 1


def test_cache_refreshes_when_configured_ttl_expires() -> None:
    private_key = _rsa_key()
    clock_values = [100.0]
    settings = _settings(auth_jwks_cache_ttl_seconds=1)
    transport = FakeTransport(_response(_jwks(_rsa_jwk(private_key))))
    store = TrustedJwksKeyStore(
        settings,
        transport=transport,
        resolver=_public_resolver,
        clock=lambda: clock_values[0],
    )
    verifier = JwtAccessTokenVerifier(settings, key_store=store)
    token = _token(private_key)

    _verify(verifier, token)
    clock_values[0] += 2
    with pytest.raises(TrustedKeySourceUnavailable):
        _verify(verifier, token)
    clock_values[0] += 4
    _verify(verifier, token)

    assert len(transport.calls) == 2


def test_key_rotation_refreshes_after_unknown_kid_cooldown() -> None:
    first_key = _rsa_key()
    rotated_key = _rsa_key()
    clock_values = [100.0]
    transport = FakeTransport(
        [
            _response(_jwks(_rsa_jwk(first_key))),
            _response(_jwks(_rsa_jwk(first_key), _rsa_jwk(rotated_key, "rotated"))),
        ]
    )
    settings = _settings()
    store = TrustedJwksKeyStore(
        settings,
        transport=transport,
        resolver=_public_resolver,
        clock=lambda: clock_values[0],
    )
    verifier = JwtAccessTokenVerifier(settings, key_store=store)
    rotated_token = jwt.encode(
        {
            "iss": "https://issuer.example/",
            "sub": "subject",
            "aud": "threat-sentinel-api",
            "iat": int(datetime.now(UTC).timestamp()),
            "exp": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp()),
        },
        rotated_key,
        algorithm="RS256",
        headers={"kid": "rotated", "typ": "at+jwt"},
    )

    with pytest.raises(InvalidAccessToken):
        _verify(verifier, rotated_token)
    clock_values[0] += 31

    claims = _verify(verifier, rotated_token)

    assert claims.subject == "subject"
    assert len(transport.calls) == 2


def test_jwks_key_count_is_bounded_by_configuration() -> None:
    private_key = _rsa_key()
    response = _response(
        _jwks(
            _rsa_jwk(private_key, "one"),
            _rsa_jwk(_rsa_key(), "two"),
        )
    )
    verifier, _ = _verifier(
        private_key,
        settings=_settings(auth_jwks_cache_max_entries=1),
        response=response,
    )

    with pytest.raises(TrustedKeySourceUnavailable):
        _verify(verifier, _token(private_key))


def test_algorithm_key_type_mismatch_is_rejected() -> None:
    private_key = _rsa_key()
    verifier, _ = _verifier(
        private_key,
        settings=_settings(auth_allowed_jwt_algorithms=["ES256"]),
    )

    with pytest.raises(InvalidAccessToken):
        _verify(verifier, _token(private_key))


def test_verifier_requires_complete_configuration_and_wraps_internal_errors() -> None:
    with pytest.raises(ValueError):
        JwtAccessTokenVerifier(Settings(_env_file=None))

    with pytest.raises(ValueError):
        JwtAccessTokenVerifier(
            _settings(auth_trusted_jwks_url=None),
            key_store=TrustedJwksKeyStore(
                _settings(),
                transport=FakeTransport(_response(_jwks(_rsa_jwk(_rsa_key())))),
                resolver=_public_resolver,
            ),
        )

    verifier, _ = _verifier(response=RuntimeError("unexpected"))
    with pytest.raises(AuthenticationVerifierFailure):
        _verify(verifier, _token(_rsa_key()))


def test_pinned_https_connection_uses_validated_ip_and_original_tls_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connected: list[tuple[str, int]] = []
    wrapped: list[str] = []

    class FakeSocket:
        def settimeout(self, _timeout: float) -> None:
            pass

        def connect(self, address: tuple[str, int]) -> None:
            connected.append(address)

        def close(self) -> None:
            pass

    class FakeTlsSocket(FakeSocket):
        pass

    class FakeTlsContext:
        def wrap_socket(self, _socket: FakeSocket, *, server_hostname: str) -> FakeTlsSocket:
            wrapped.append(server_hostname)
            return FakeTlsSocket()

    monkeypatch.setattr(
        "threat_sentinel_api.modules.identity.jwks.socket.socket", lambda *_args: FakeSocket()
    )
    connection = _PinnedHttpsConnection(
        "trusted.example",
        443,
        ipaddress.ip_address("93.184.216.34"),
        3.0,
        FakeTlsContext(),  # type: ignore[arg-type]
    )
    try:
        connection.connect()
    finally:
        connection.close()

    assert connected == [("93.184.216.34", 443)]
    assert wrapped == ["trusted.example"]


def test_transport_rejects_prohibited_addresses_even_if_called_directly() -> None:
    with pytest.raises(TrustedKeySourceUnavailable):
        PinnedHttpsTransport().get(
            "https://trusted.example/jwks",
            [ipaddress.ip_address("127.0.0.1")],
            timeout=3.0,
            max_bytes=1024,
        )
