from hashlib import sha256
import time
from collections.abc import Callable

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.resolver
import pytest

from threat_sentinel_api.modules.targets.dns_verification import (
    DNS_QUERY_TIMEOUT_SECONDS,
    DNSChallengeVerifier,
    DNSVerificationError,
    _SystemDNSMessageQuery,
)


class FixtureDNSQuery:
    def __init__(
        self,
        *responses: dns.message.Message
        | Exception
        | Callable[[dns.message.Message], dns.message.Message],
    ) -> None:
        self.responses = list(responses)
        self.requests: list[dns.message.Message] = []

    def query(
        self,
        request: dns.message.Message,
        *,
        deadline: float,
    ) -> dns.message.Message:
        self.requests.append(request)
        response = self.responses.pop(0)
        if callable(response):
            return response(request)
        if isinstance(response, Exception):
            raise response
        return response


def txt_response(request: dns.message.Message, *records: str) -> dns.message.Message:
    response = dns.message.make_response(request)
    if records:
        response.answer.append(
            dns.rrset.from_text(
                request.question[0].name,
                60,
                "IN",
                "TXT",
                *records,
            )
        )
    return response


def cname_response(request: dns.message.Message, target: str) -> dns.message.Message:
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text(
            request.question[0].name,
            60,
            "IN",
            "CNAME",
            target,
        )
    )
    return response


def txt_fixture(
    *records: str,
) -> Callable[[dns.message.Message], dns.message.Message]:
    return lambda request: txt_response(request, *records)


def cname_fixture(target: str) -> Callable[[dns.message.Message], dns.message.Message]:
    return lambda request: cname_response(request, target)


def challenge_hash(value: str) -> str:
    return sha256(value.encode("ascii")).hexdigest()


def verify(query: FixtureDNSQuery, challenge: str = "challenge-value") -> None:
    DNSChallengeVerifier(query).verify_challenge("example.com", challenge_hash(challenge))


def test_queries_exact_owner_name_and_matches_one_txt_record() -> None:
    query = FixtureDNSQuery(txt_fixture('"unrelated"', '"challenge-value"'))

    verify(query)

    assert len(query.requests) == 1
    assert query.requests[0].question[0].name.to_text() == (
        "_threatsentinel-verification.example.com."
    )
    assert query.requests[0].question[0].rdtype == dns.rdatatype.TXT


def test_concatenates_character_strings_within_one_txt_record() -> None:
    query = FixtureDNSQuery(txt_fixture('"challenge-" "value"'))

    verify(query)


def test_follows_valid_cname_before_matching_txt_record() -> None:
    alias = "verification-alias.example.net."
    query = FixtureDNSQuery(
        cname_fixture(alias),
        txt_fixture('"challenge-value"'),
    )

    verify(query)

    assert [request.question[0].name.to_text() for request in query.requests] == [
        "_threatsentinel-verification.example.com.",
        alias,
    ]


@pytest.mark.parametrize(
    "record",
    [
        '"prefix-challenge-value-suffix"',
        '"challenge"',
        '" challenge-value"',
        '"challenge-value "',
        '"CHALLENGE-VALUE"',
    ],
)
def test_rejects_non_exact_txt_values(record: str) -> None:
    query = FixtureDNSQuery(txt_fixture(record))

    with pytest.raises(DNSVerificationError):
        verify(query)


def test_never_concatenates_separate_txt_records() -> None:
    query = FixtureDNSQuery(txt_fixture('"challenge-"', '"value"'))

    with pytest.raises(DNSVerificationError):
        verify(query)


def test_rejects_absent_txt_records() -> None:
    with pytest.raises(DNSVerificationError):
        verify(FixtureDNSQuery(txt_fixture()))


@pytest.mark.parametrize("malformation", ["wrong-id", "wrong-question", "nxdomain", "truncated"])
def test_rejects_malformed_or_incomplete_responses(malformation: str) -> None:
    def malformed_response(request: dns.message.Message) -> dns.message.Message:
        response = txt_response(request, '"challenge-value"')
        if malformation == "wrong-id":
            response.id = (response.id + 1) % 65536
        elif malformation == "wrong-question":
            response.question = [dns.rrset.from_text("other.example.com.", 0, "IN", "TXT", '""')]
        elif malformation == "nxdomain":
            response.set_rcode(dns.rcode.NXDOMAIN)
        else:
            response.flags |= dns.flags.TC
        return response

    with pytest.raises(DNSVerificationError):
        verify(FixtureDNSQuery(malformed_response))


def test_resolver_timeout_fails_closed() -> None:
    with pytest.raises(DNSVerificationError):
        verify(FixtureDNSQuery(dns.exception.Timeout("fixture timeout")))


@pytest.mark.parametrize(
    ("section", "record"),
    [
        ("authority", ("example.com.", "IN", "NS", "ns.example.com.")),
        ("additional", ("ns.example.com.", "IN", "A", "192.0.2.1")),
        ("authority", ("example.com.", "CH", "TXT", '"challenge-value"')),
        ("additional", ("example.com.", "CH", "CNAME", "alias.example.net.")),
    ],
)
def test_rejects_unsupported_authority_and_additional_records(
    section: str,
    record: tuple[str, str, str, str],
) -> None:
    def response_with_unsupported_record(request: dns.message.Message) -> dns.message.Message:
        response = txt_response(request, '"challenge-value"')
        rrset = dns.rrset.from_text(record[0], 60, record[1], record[2], record[3])
        getattr(response, section).append(rrset)
        return response

    with pytest.raises(DNSVerificationError):
        verify(FixtureDNSQuery(response_with_unsupported_record))


def test_rejects_cname_loops() -> None:
    initial = "_threatsentinel-verification.example.com."
    alias = "alias.example.net."
    query = FixtureDNSQuery(
        cname_fixture(alias),
        cname_fixture(initial),
    )

    with pytest.raises(DNSVerificationError):
        verify(query)
    assert len(query.requests) == 2


def test_rejects_cname_chains_over_limit() -> None:
    responses: list[Callable[[dns.message.Message], dns.message.Message]] = []
    for index in range(9):
        target = f"alias-{index}.example.net."
        responses.append(cname_fixture(target))

    query = FixtureDNSQuery(*responses)
    with pytest.raises(DNSVerificationError):
        verify(query)
    assert len(query.requests) == 9


def test_system_query_retries_truncated_udp_over_tcp(monkeypatch: pytest.MonkeyPatch) -> None:
    request = dns.message.make_query(
        "_threatsentinel-verification.example.com.",
        dns.rdatatype.TXT,
    )
    truncated = dns.message.make_response(request)
    truncated.flags |= dns.flags.TC
    complete = txt_response(request, '"challenge-value"')
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["192.0.2.53"]
    initial_time = 100.0
    elapsed_udp_time = 1.25
    current_time = [initial_time]
    udp_calls: list[tuple[str, int, float]] = []
    tcp_calls: list[tuple[str, int, float]] = []

    def fake_monotonic() -> float:
        return current_time[0]

    def fake_udp(
        _request: dns.message.Message,
        _nameserver: str,
        *,
        timeout: float,
        port: int,
    ) -> dns.message.Message:
        udp_calls.append((_nameserver, port, timeout))
        assert timeout > 0
        assert port == 53
        current_time[0] += elapsed_udp_time
        return truncated

    def fake_tcp(
        _request: dns.message.Message,
        _nameserver: str,
        *,
        timeout: float,
        port: int,
    ) -> dns.message.Message:
        tcp_calls.append((_nameserver, port, timeout))
        assert timeout > 0
        assert port == 53
        return complete

    monkeypatch.setattr(
        "threat_sentinel_api.modules.targets.dns_verification.time.monotonic",
        fake_monotonic,
    )
    monkeypatch.setattr("dns.query.udp", fake_udp)
    monkeypatch.setattr("dns.query.tcp", fake_tcp)
    transport = _SystemDNSMessageQuery()
    transport._resolver = resolver

    result = transport.query(
        request,
        deadline=initial_time + DNS_QUERY_TIMEOUT_SECONDS,
    )

    assert result is complete
    assert len(udp_calls) == 1
    assert len(tcp_calls) == 1
    udp_nameserver, udp_port, udp_timeout = udp_calls[0]
    tcp_nameserver, tcp_port, tcp_timeout = tcp_calls[0]
    assert udp_timeout > 0
    assert udp_timeout <= DNS_QUERY_TIMEOUT_SECONDS
    assert tcp_timeout > 0
    assert tcp_timeout < udp_timeout
    assert tcp_timeout <= DNS_QUERY_TIMEOUT_SECONDS - elapsed_udp_time
    assert udp_nameserver == tcp_nameserver == resolver.nameservers[0]
    assert udp_port == tcp_port == resolver.port == 53


def test_tries_later_configured_nameserver_after_first_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = dns.message.make_query(
        "_threatsentinel-verification.example.com.",
        dns.rdatatype.TXT,
    )
    complete = txt_response(request, '"challenge-value"')
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["192.0.2.53", "2001:db8::53"]
    attempts: list[tuple[str, float]] = []

    def fake_udp(
        query: dns.message.Message,
        nameserver: str,
        *,
        timeout: float,
        port: int,
    ) -> dns.message.Message:
        attempts.append((nameserver, timeout))
        if nameserver == "192.0.2.53":
            raise dns.exception.Timeout("fixture timeout")
        return complete

    monkeypatch.setattr("dns.query.udp", fake_udp)
    transport = _SystemDNSMessageQuery()
    transport._resolver = resolver

    result = transport.query(request, deadline=time.monotonic() + 10)

    assert result is complete
    assert [nameserver for nameserver, _ in attempts] == [
        "192.0.2.53",
        "2001:db8::53",
    ]
    assert attempts[0][1] <= DNS_QUERY_TIMEOUT_SECONDS
    assert attempts[1][1] <= attempts[0][1]


def test_all_configured_nameservers_fail_within_one_query_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = dns.message.make_query(
        "_threatsentinel-verification.example.com.",
        dns.rdatatype.TXT,
    )
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["192.0.2.53", "2001:db8::53", "192.0.2.54"]
    attempts: list[tuple[str, float]] = []
    now = [100.0]

    def fake_monotonic() -> float:
        return now[0]

    def fake_udp(
        _request: dns.message.Message,
        nameserver: str,
        *,
        timeout: float,
        port: int,
    ) -> dns.message.Message:
        attempts.append((nameserver, timeout))
        now[0] += 1.0
        raise dns.exception.Timeout("fixture timeout")

    monkeypatch.setattr(
        "threat_sentinel_api.modules.targets.dns_verification.time.monotonic",
        fake_monotonic,
    )
    monkeypatch.setattr("dns.query.udp", fake_udp)
    transport = _SystemDNSMessageQuery()
    transport._resolver = resolver

    with pytest.raises(DNSVerificationError):
        transport.query(request, deadline=now[0] + 10)

    assert [nameserver for nameserver, _ in attempts] == [
        "192.0.2.53",
        "2001:db8::53",
        "192.0.2.54",
    ]
    assert [timeout for _, timeout in attempts] == [3.0, 2.0, 1.0]


def test_rejects_unsupported_system_nameserver_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = dns.message.make_query(
        "_threatsentinel-verification.example.com.",
        dns.rdatatype.TXT,
    )
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns.nameserver.DoHNameserver("https://resolver.example.net/dns-query")]
    monkeypatch.setattr("dns.query.udp", lambda *_args, **_kwargs: pytest.fail("unexpected DNS"))
    transport = _SystemDNSMessageQuery()
    transport._resolver = resolver

    with pytest.raises(DNSVerificationError):
        transport.query(request, deadline=time.monotonic() + 3)


def test_rejects_response_still_truncated_after_tcp_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = dns.message.make_query(
        "_threatsentinel-verification.example.com.",
        dns.rdatatype.TXT,
    )
    truncated = dns.message.make_response(request)
    truncated.flags |= dns.flags.TC
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["192.0.2.53"]

    monkeypatch.setattr("dns.query.udp", lambda *_args, **_kwargs: truncated)
    monkeypatch.setattr("dns.query.tcp", lambda *_args, **_kwargs: truncated)
    transport = _SystemDNSMessageQuery()
    transport._resolver = resolver

    with pytest.raises(DNSVerificationError):
        DNSChallengeVerifier(transport).verify_challenge(
            "example.com",
            challenge_hash("challenge-value"),
        )


def test_overall_deadline_exhaustion_across_cname_queries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_time = [100.0]
    query_count = 0

    def fake_monotonic() -> float:
        return current_time[0]

    def slow_cname_response(request: dns.message.Message) -> dns.message.Message:
        nonlocal query_count
        query_count += 1
        response = cname_response(request, f"alias-{query_count}.example.net.")
        current_time[0] += 4.0
        return response

    monkeypatch.setattr(
        "threat_sentinel_api.modules.targets.dns_verification.time.monotonic",
        fake_monotonic,
    )

    with pytest.raises(DNSVerificationError):
        verify(FixtureDNSQuery(slow_cname_response, slow_cname_response, slow_cname_response))

    assert query_count == 3
