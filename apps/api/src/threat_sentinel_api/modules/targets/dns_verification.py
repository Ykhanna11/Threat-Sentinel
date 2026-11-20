"""Bounded DNS TXT verification for organization target ownership challenges."""

from __future__ import annotations

from hashlib import sha256
import hmac
import ipaddress
import re
import time
from typing import Protocol

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
from dns.rdtypes.ANY.CNAME import CNAME
from dns.rdtypes.ANY.TXT import TXT


DNS_QUERY_TIMEOUT_SECONDS = 3.0
DNS_RESOLUTION_DEADLINE_SECONDS = 10.0
MAX_CNAME_LINKS = 8
MAX_DNS_MESSAGE_SIZE = 64 * 1024
MAX_DNS_RESOURCE_RECORDS = 128
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class DNSVerificationError(RuntimeError):
    """A safe, non-sensitive failure to resolve or match the ownership TXT proof."""

    def __init__(self) -> None:
        super().__init__("DNS ownership verification failed.")


class DNSMessageQuery(Protocol):
    def query(
        self,
        request: dns.message.Message,
        *,
        deadline: float,
    ) -> dns.message.Message: ...


class DNSChallengeVerification(Protocol):
    def verify_challenge(self, hostname: str, expected_hash: str) -> None: ...


class _SystemDNSMessageQuery:
    def __init__(self) -> None:
        self._resolver = dns.resolver.Resolver(configure=True)

    def query(
        self,
        request: dns.message.Message,
        *,
        deadline: float,
    ) -> dns.message.Message:
        nameservers = self._configured_nameservers()
        if not nameservers:
            raise DNSVerificationError()

        query_deadline = min(deadline, time.monotonic() + DNS_QUERY_TIMEOUT_SECONDS)
        for nameserver in nameservers:
            timeout = query_deadline - time.monotonic()
            if timeout <= 0:
                raise DNSVerificationError()
            try:
                response = dns.query.udp(
                    request,
                    nameserver,
                    timeout=timeout,
                    port=self._resolver.port,
                )
                if response.flags & dns.flags.TC:
                    timeout = query_deadline - time.monotonic()
                    if timeout <= 0:
                        raise DNSVerificationError()
                    response = dns.query.tcp(
                        request,
                        nameserver,
                        timeout=timeout,
                        port=self._resolver.port,
                    )
                return response
            except DNSVerificationError:
                raise
            except (dns.exception.DNSException, OSError, TimeoutError):
                continue
        raise DNSVerificationError()

    def _configured_nameservers(self) -> tuple[str, ...]:
        configured: list[str] = []
        for nameserver in self._resolver.nameservers:
            if not isinstance(nameserver, str):
                raise DNSVerificationError()
            try:
                ipaddress.ip_address(nameserver)
            except ValueError:
                raise DNSVerificationError() from None
            configured.append(nameserver)
        return tuple(configured)


class DNSChallengeVerifier:
    """Resolve the exact TXT owner using the host's configured recursive resolver."""

    def __init__(self, query: DNSMessageQuery | None = None) -> None:
        self._query = query

    def verify_challenge(self, hostname: str, expected_hash: str) -> None:
        if not isinstance(expected_hash, str) or _SHA256_HEX.fullmatch(expected_hash) is None:
            raise DNSVerificationError()

        try:
            owner = dns.name.from_text(
                f"_threatsentinel-verification.{hostname}.",
                origin=dns.name.root,
            )
            deadline = time.monotonic() + DNS_RESOLUTION_DEADLINE_SECONDS
            query = self._query if self._query is not None else _SystemDNSMessageQuery()
            self._resolve_and_match(owner, expected_hash, query, deadline)
        except DNSVerificationError:
            raise
        except (
            dns.exception.DNSException,
            OSError,
            TimeoutError,
            ValueError,
        ):
            raise DNSVerificationError() from None

    @classmethod
    def _resolve_and_match(
        cls,
        owner: dns.name.Name,
        expected_hash: str,
        query: DNSMessageQuery,
        deadline: float,
    ) -> None:
        current = owner.canonicalize()
        visited: set[dns.name.Name] = set()
        cname_links = 0

        while True:
            if time.monotonic() >= deadline or current in visited:
                raise DNSVerificationError()
            visited.add(current)

            request = dns.message.make_query(
                current,
                dns.rdatatype.TXT,
                dns.rdataclass.IN,
            )
            response = query.query(request, deadline=deadline)
            if time.monotonic() >= deadline:
                raise DNSVerificationError()
            cls._validate_response(response, request)
            rrsets = response.answer
            rrsets_by_owner: dict[dns.name.Name, list[dns.rrset.RRset]] = {}
            for rrset in rrsets:
                rrsets_by_owner.setdefault(rrset.name.canonicalize(), []).append(rrset)

            response_owners: set[dns.name.Name] = set()
            while current in rrsets_by_owner:
                if current in response_owners:
                    raise DNSVerificationError()
                response_owners.add(current)
                current_rrsets = rrsets_by_owner[current]
                cname_rrsets = [
                    rrset for rrset in current_rrsets if rrset.rdtype == dns.rdatatype.CNAME
                ]
                txt_rrsets = [
                    rrset for rrset in current_rrsets if rrset.rdtype == dns.rdatatype.TXT
                ]
                if len(cname_rrsets) > 1 or len(txt_rrsets) > 1 or (cname_rrsets and txt_rrsets):
                    raise DNSVerificationError()

                if cname_rrsets:
                    cname_rrset = cname_rrsets[0]
                    if len(cname_rrset) != 1:
                        raise DNSVerificationError()
                    cname_record = next(iter(cname_rrset))
                    if not isinstance(cname_record, CNAME):
                        raise DNSVerificationError()
                    target = cname_record.target.canonicalize()
                    cname_links += 1
                    if (
                        cname_links > MAX_CNAME_LINKS
                        or target == dns.name.root
                        or target in visited
                    ):
                        raise DNSVerificationError()
                    current = target
                    continue

                if txt_rrsets:
                    if response_owners != set(rrsets_by_owner):
                        raise DNSVerificationError()
                    if any(
                        cls._txt_record_matches(record, expected_hash) for record in txt_rrsets[0]
                    ):
                        return
                    raise DNSVerificationError()

                raise DNSVerificationError()

            if response_owners != set(rrsets_by_owner):
                raise DNSVerificationError()
            if not response_owners:
                raise DNSVerificationError()

    @staticmethod
    def _validate_response(
        response: dns.message.Message,
        request: dns.message.Message,
    ) -> None:
        if (
            response.id != request.id
            or not response.flags & dns.flags.QR
            or response.flags & dns.flags.TC
            or response.opcode() != dns.opcode.QUERY
            or response.rcode() != dns.rcode.NOERROR
            or len(response.question) != 1
            or response.question != request.question
        ):
            raise DNSVerificationError()

        sections = (response.answer, response.authority, response.additional)
        record_count = sum(len(rrset) for section in sections for rrset in section)
        if (
            record_count > MAX_DNS_RESOURCE_RECORDS
            or len(response.to_wire()) > MAX_DNS_MESSAGE_SIZE
            or any(
                rrset.rdclass != dns.rdataclass.IN
                or rrset.rdtype not in {dns.rdatatype.CNAME, dns.rdatatype.TXT}
                for rrset in response.answer
            )
            or response.authority
            or response.additional
        ):
            raise DNSVerificationError()

    @staticmethod
    def _txt_record_matches(record: object, expected_hash: str) -> bool:
        if not isinstance(record, TXT):
            raise DNSVerificationError()
        chunks = record.strings
        if not chunks or any(not isinstance(chunk, bytes) for chunk in chunks):
            raise DNSVerificationError()
        actual_hash = sha256(b"".join(chunks)).hexdigest()
        return hmac.compare_digest(actual_hash, expected_hash)
