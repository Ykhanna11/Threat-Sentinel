import pytest

from threat_sentinel_api.modules.targets.hostname import (
    CanonicalHostname,
    HostnameCanonicalizationError,
    HostnameErrorCode,
    canonicalize_hostname,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        ("WwW.ExAmPlE.CoM.", "www.example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("faß.de", "xn--fa-hia.de"),
        ("e\u0301xample.com", "xn--xample-9ua.com"),
        ("éxample.com", "xn--xample-9ua.com"),
        ("example。com", "example.com"),
        ("ｅｘａｍｐｌｅ.com", "example.com"),
    ],
)
def test_canonicalize_hostname_returns_lowercase_ascii_alabels(
    value: str,
    expected: str,
) -> None:
    canonical = canonicalize_hostname(value)

    assert type(canonical) is CanonicalHostname
    assert canonical == expected
    assert canonical.isascii()
    assert canonical == canonical.lower()


def test_idna_uses_non_transitional_processing() -> None:
    canonical = canonicalize_hostname("faß.de")

    assert canonical == "xn--fa-hia.de"
    assert canonical != "fass.de"


def test_composed_and_decomposed_unicode_have_identical_canonical_output() -> None:
    composed = canonicalize_hostname("éxample.com")
    decomposed = canonicalize_hostname("e\u0301xample.com")

    assert composed == decomposed


def test_canonical_alabel_round_trips_through_the_validated_type() -> None:
    alabel = canonicalize_hostname("bücher.example")

    assert canonicalize_hostname(alabel) == alabel
    assert CanonicalHostname(alabel) == alabel


def test_single_trailing_root_dot_is_removed() -> None:
    assert canonicalize_hostname("example.com.") == "example.com"


def test_maximum_ascii_label_length_is_accepted() -> None:
    hostname = f"{'a' * 63}.example"

    assert canonicalize_hostname(hostname) == hostname


def test_label_longer_than_63_ascii_octets_is_rejected() -> None:
    with pytest.raises(HostnameCanonicalizationError) as error:
        canonicalize_hostname(f"{'a' * 64}.example")

    assert error.value.code is HostnameErrorCode.LABEL_TOO_LONG


def test_maximum_253_octet_hostname_is_accepted() -> None:
    hostname = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))

    assert len(hostname.encode("ascii")) == 253
    assert canonicalize_hostname(hostname) == hostname
    assert canonicalize_hostname(f"{hostname}.") == hostname


def test_hostname_over_253_octets_is_rejected() -> None:
    hostname = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 62))

    with pytest.raises(HostnameCanonicalizationError) as error:
        canonicalize_hostname(hostname)

    assert error.value.code is HostnameErrorCode.HOSTNAME_TOO_LONG


def test_maximum_label_count_allowed_by_the_octet_limit_is_accepted() -> None:
    hostname = ".".join(["a"] * 127)

    assert len(hostname.encode("ascii")) == 253
    assert canonicalize_hostname(hostname) == hostname


def test_more_than_253_octets_from_many_labels_is_rejected() -> None:
    hostname = ".".join(["a"] * 128)

    with pytest.raises(HostnameCanonicalizationError):
        canonicalize_hostname(hostname)


@pytest.mark.parametrize(
    "value",
    [
        "",
        ".example.com",
        "example..com",
        "example.com..",
        "example.com...",
        "localhost",
        "-example.com",
        "example-.com",
        "exa_mple.com",
        "*.example.com",
        "http://example.com",
        "https://example.com",
        "example.com:443",
        "user@example.com",
        "example.com/path",
        "example.com?query",
        "example.com#fragment",
        r"example\com",
        "example%2ecom",
        "example∕com",
        " example.com",
        "example.com ",
        "example .com",
        "example\t.com",
        "\x00example.com",
        "example.com\x7f",
        "\ud800.example",
    ],
)
def test_malformed_or_ambiguous_names_are_rejected(value: str) -> None:
    with pytest.raises(HostnameCanonicalizationError):
        canonicalize_hostname(value)


@pytest.mark.parametrize(
    "value",
    [
        "192.0.2.1",
        "192.0.2.1.",
        "2001:db8::1",
        "[2001:db8::1]",
        "[192.0.2.1]",
        "１２７.0.0.1",
    ],
)
def test_ip_literals_are_rejected(value: str) -> None:
    with pytest.raises(HostnameCanonicalizationError) as error:
        canonicalize_hostname(value)

    assert error.value.code is HostnameErrorCode.IP_LITERAL


@pytest.mark.parametrize(
    "value",
    [
        "127.1",
        "0177.0.0.1",
        "0x7f000001",
        "0x7f.1",
        "0o177.0.0.1",
        "2130706433",
        "1.2.3",
    ],
)
def test_ambiguous_numeric_ip_forms_are_rejected(value: str) -> None:
    with pytest.raises(HostnameCanonicalizationError) as error:
        canonicalize_hostname(value)

    assert error.value.code is HostnameErrorCode.IP_ADDRESS_LIKE


@pytest.mark.parametrize(
    "value",
    [
        "xn--",
        "xn--a.example",
        "xn--invalid-.example",
        "a\u200cb.example",
        "a\u200db.example",
        "abcא.example",
        f"{'界' * 70}.example",
    ],
)
def test_invalid_alabels_and_idna_constraints_are_rejected(value: str) -> None:
    with pytest.raises(HostnameCanonicalizationError):
        canonicalize_hostname(value)


def test_canonical_hostname_constructor_canonicalizes_regular_construction() -> None:
    valid = CanonicalHostname("BÜCHER.example.")

    assert valid == "xn--bcher-kva.example"

    with pytest.raises(HostnameCanonicalizationError):
        CanonicalHostname("https://attacker.example")


def test_canonicalize_hostname_revalidates_forged_subtype() -> None:
    forged = str.__new__(CanonicalHostname, "https://attacker.example")

    assert type(forged) is CanonicalHostname
    with pytest.raises(HostnameCanonicalizationError) as error:
        canonicalize_hostname(forged)

    assert error.value.code is HostnameErrorCode.INVALID_FORMAT


def test_error_code_is_stable_and_does_not_expose_raw_input() -> None:
    secret_input = "https://private-host.example/path"

    with pytest.raises(HostnameCanonicalizationError) as error:
        canonicalize_hostname(secret_input)

    assert error.value.code is HostnameErrorCode.INVALID_FORMAT
    assert str(error.value) == "invalid_format"
    assert secret_input not in str(error.value)
    assert "private-host" not in str(error.value)


def test_idna_error_does_not_expose_library_exception_or_raw_input() -> None:
    invalid_alabel = "xn--a.private.example"

    with pytest.raises(HostnameCanonicalizationError) as error:
        canonicalize_hostname(invalid_alabel)

    assert error.value.code is HostnameErrorCode.INVALID_IDNA
    assert str(error.value) == "invalid_idna"
    assert invalid_alabel not in str(error.value)
    assert error.value.__suppress_context__


def test_non_string_input_is_rejected_with_stable_error_code() -> None:
    with pytest.raises(HostnameCanonicalizationError) as error:
        canonicalize_hostname(123)  # type: ignore[arg-type]

    assert error.value.code is HostnameErrorCode.INVALID_TYPE


def test_equivalent_valid_inputs_always_produce_the_same_typed_value() -> None:
    inputs = ("Example.COM", "example.com", "EXAMPLE.com.")
    canonical = [canonicalize_hostname(value) for value in inputs]

    assert canonical == [CanonicalHostname("example.com")] * len(inputs)
