"""Hostname syntax validation and canonicalization.

``CanonicalHostname`` is a convenience string subtype, not proof of validation,
authorization, or ownership. Consumers must call ``canonicalize_hostname`` at
each trust boundary before DNS resolution, persistence, or network access;
runtime type identity and annotations are not security controls.
"""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from typing import NoReturn, Self, final

import idna


_FORBIDDEN_CHARACTERS = frozenset(":/\\?#@*%[]")
_NUMERIC_ADDRESS_LABEL = re.compile(
    r"(?:[0-9]+|0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+)\Z",
    re.ASCII,
)


class HostnameErrorCode(StrEnum):
    INVALID_TYPE = "invalid_type"
    EMPTY_HOSTNAME = "empty_hostname"
    INVALID_FORMAT = "invalid_format"
    IP_LITERAL = "ip_literal"
    IP_ADDRESS_LIKE = "ip_address_like"
    SINGLE_LABEL = "single_label"
    INVALID_IDNA = "invalid_idna"
    LABEL_TOO_LONG = "label_too_long"
    HOSTNAME_TOO_LONG = "hostname_too_long"


class HostnameCanonicalizationError(ValueError):
    def __init__(self, code: HostnameErrorCode) -> None:
        self.code = code
        super().__init__(code.value)


def _reject(code: HostnameErrorCode) -> NoReturn:
    raise HostnameCanonicalizationError(code) from None


def _is_ip_literal(value: str) -> bool:
    candidates = [value]
    if value.endswith("."):
        candidates.append(value[:-1])
    if value.startswith("[") and value.endswith("]"):
        candidates.append(value[1:-1])

    for candidate in candidates:
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return True

    return False


def _is_numeric_address_name(labels: list[str]) -> bool:
    return all(_NUMERIC_ADDRESS_LABEL.fullmatch(label) is not None for label in labels)


def _canonicalize(value: str) -> str:
    if not isinstance(value, str):
        _reject(HostnameErrorCode.INVALID_TYPE)
    if not value:
        _reject(HostnameErrorCode.EMPTY_HOSTNAME)
    if any(character.isspace() for character in value):
        _reject(HostnameErrorCode.INVALID_FORMAT)
    if _is_ip_literal(value):
        _reject(HostnameErrorCode.IP_LITERAL)
    if any(character in _FORBIDDEN_CHARACTERS for character in value):
        _reject(HostnameErrorCode.INVALID_FORMAT)

    try:
        mapped = idna.uts46_remap(value, std3_rules=True, transitional=False)
    except idna.IDNAError:
        _reject(HostnameErrorCode.INVALID_IDNA)

    if _is_ip_literal(mapped):
        _reject(HostnameErrorCode.IP_LITERAL)

    if mapped.endswith(".."):
        _reject(HostnameErrorCode.INVALID_FORMAT)
    if mapped.endswith("."):
        mapped = mapped[:-1]
    if not mapped:
        _reject(HostnameErrorCode.EMPTY_HOSTNAME)

    labels = mapped.split(".")
    if any(not label for label in labels):
        _reject(HostnameErrorCode.INVALID_FORMAT)
    if _is_numeric_address_name(labels):
        _reject(HostnameErrorCode.IP_ADDRESS_LIKE)
    if len(labels) < 2:
        _reject(HostnameErrorCode.SINGLE_LABEL)

    ascii_labels: list[bytes] = []
    for label in labels:
        if label.isascii() and len(label) > 63:
            _reject(HostnameErrorCode.LABEL_TOO_LONG)
        try:
            ascii_label = idna.encode(
                label,
                strict=True,
                uts46=False,
                std3_rules=True,
            )
            decoded_label = idna.decode(
                ascii_label,
                strict=True,
                uts46=False,
                std3_rules=True,
            )
            round_trip = idna.encode(
                decoded_label,
                strict=True,
                uts46=False,
                std3_rules=True,
            )
        except idna.IDNAError:
            _reject(HostnameErrorCode.INVALID_IDNA)
        if ascii_label.lower() != round_trip.lower():
            _reject(HostnameErrorCode.INVALID_IDNA)
        if len(ascii_label) > 63:
            _reject(HostnameErrorCode.LABEL_TOO_LONG)
        ascii_labels.append(ascii_label.lower())

    canonical = b".".join(ascii_labels)
    if len(canonical) > 253:
        _reject(HostnameErrorCode.HOSTNAME_TOO_LONG)
    return canonical.decode("ascii")


@final
class CanonicalHostname(str):
    """Canonicalization result subtype; not an enforceable validation boundary."""

    __slots__ = ()

    def __new__(cls, value: str) -> Self:
        return str.__new__(cls, _canonicalize(value))


def canonicalize_hostname(value: str) -> CanonicalHostname:
    """Validate and canonicalize input; this does not prove DNS ownership or scan permission."""
    return CanonicalHostname(value)
