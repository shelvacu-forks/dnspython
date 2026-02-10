# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import struct
import ipaddress
from typing import Any, IO, Self

import dns.immutable
import dns.ipv4
import dns.rdata


@dns.immutable.immutable
class L32(dns.rdata.Rdata):
    """L32 record"""

    # see: rfc6742.txt

    __slots__ = ["preference", "locator32"]

    preference: int
    locator32: str

    def __init__(
        self,
        rdclass: dns.rdataclass.RdataClass,
        rdtype: dns.rdatatype.RdataType,
        preference: int,
        locator32: str | bytes | ipaddress.IPv4Address,
    ) -> None:
        super().__init__(rdclass, rdtype)
        self.preference = self._as_uint16(preference)
        self.locator32 = self._as_ipv4_address(locator32)

    def to_text(self, origin: dns.name.Name | None = None, relativize: bool = True, **kw: Any) -> str:
        return f"{self.preference} {self.locator32}"

    @classmethod
    def from_text(
        cls, rdclass: dns.rdataclass.RdataClass, rdtype: dns.rdatatype.RdataType, tok: dns.tokenizer.Tokenizer, origin: dns.name.Name | None = None, relativize: bool = True, relativize_to: dns.name.Name | None = None
    ):
        preference = tok.get_uint16()
        nodeid = tok.get_identifier()
        return cls(rdclass, rdtype, preference, nodeid)

    def _to_wire(self, file: IO[bytes], compress: dns.name.CompressType | None = None, origin: dns.name.Name | None = None, canonicalize: bool = False) -> None:
        file.write(struct.pack("!H", self.preference))
        file.write(dns.ipv4.inet_aton(self.locator32))

    @classmethod
    def from_wire_parser(cls, rdclass: dns.rdataclass.RdataClass, rdtype: dns.rdatatype.RdataType, parser: dns.wire.Parser, origin: dns.name.Name | None = None) -> Self:
        preference = parser.get_uint16()
        locator32 = parser.get_remaining()
        return cls(rdclass, rdtype, preference, locator32)
