# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import struct
from typing import Any, IO, Self

import dns.immutable
import dns.rdata


@dns.immutable.immutable
class LP(dns.rdata.Rdata):
    """LP record"""

    # see: rfc6742.txt

    __slots__ = ["preference", "fqdn"]
    preference: int
    fqdn: dns.name.Name

    def __init__(
        self,
        rdclass: dns.rdataclass.RdataClass,
        rdtype: dns.rdatatype.RdataType,
        preference: int,
        fqdn: str | dns.name.Name,
    ) -> None:
        super().__init__(rdclass, rdtype)
        self.preference = self._as_uint16(preference)
        self.fqdn = self._as_name(fqdn)

    def to_text(self, origin: dns.name.Name | None = None, relativize: bool = True, **kw: Any) -> str:
        fqdn = self.fqdn.choose_relativity(origin, relativize)
        return f"{self.preference} {fqdn}"

    @classmethod
    def from_text(
        cls, rdclass: dns.rdataclass.RdataClass, rdtype: dns.rdatatype.RdataType, tok: dns.tokenizer.Tokenizer, origin: dns.name.Name | None = None, relativize: bool = True, relativize_to: dns.name.Name | None = None
    ):
        preference = tok.get_uint16()
        fqdn = tok.get_name(origin, relativize, relativize_to)
        return cls(rdclass, rdtype, preference, fqdn)

    def _to_wire(self, file: IO[bytes], compress: dns.name.CompressType | None = None, origin: dns.name.Name | None = None, canonicalize: bool = False) -> None:
        file.write(struct.pack("!H", self.preference))
        self.fqdn.to_wire(file, compress, origin, canonicalize)

    @classmethod
    def from_wire_parser(cls, rdclass: dns.rdataclass.RdataClass, rdtype: dns.rdatatype.RdataType, parser: dns.wire.Parser, origin: dns.name.Name | None = None) -> Self:
        preference = parser.get_uint16()
        fqdn = parser.get_name(origin)
        return cls(rdclass, rdtype, preference, fqdn)
