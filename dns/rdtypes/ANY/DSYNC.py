# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import struct
from typing import Any, IO, Self

import dns.enum
import dns.exception
import dns.immutable
import dns.rdata
import dns.rdatatype


class UnknownScheme(dns.exception.DNSException):
    """Unknown DSYNC scheme"""


class Scheme(dns.enum.IntEnum):
    """DSYNC SCHEME"""

    NOTIFY = 1

    @classmethod
    def _maximum(cls):
        return 255

    @classmethod
    def _unknown_exception_class(cls):
        return UnknownScheme


@dns.immutable.immutable
class DSYNC(dns.rdata.Rdata):
    """DSYNC record"""

    # see: draft-ietf-dnsop-generalized-notify

    __slots__ = ["rrtype", "scheme", "port", "target"]

    def __init__(
        self,
        rdclass: dns.rdataclass.RdataClass,
        rdtype: dns.rdatatype.RdataType,
        rrtype: dns.rdatatype.RdataType,
        scheme: int | str | Scheme,
        port: int,
        target: dns.name.Name | str,
    ) -> None:
        super().__init__(rdclass, rdtype)
        self.rrtype = self._as_rdatatype(rrtype)
        self.scheme = Scheme.make(scheme)
        self.port = self._as_uint16(port)
        self.target = self._as_name(target)

    def to_text(self, origin: dns.name.Name | None = None, relativize: bool = True, **kw: Any) -> str:
        target = self.target.choose_relativity(origin, relativize)
        return (
            f"{dns.rdatatype.to_text(self.rrtype)} {Scheme.to_text(self.scheme)} "
            f"{self.port} {target}"
        )

    @classmethod
    def from_text(
        cls, rdclass: dns.rdataclass.RdataClass, rdtype: dns.rdatatype.RdataType, tok: dns.tokenizer.Tokenizer, origin: dns.name.Name | None = None, relativize: bool = True, relativize_to: dns.name.Name | None = None
    ):
        rrtype = dns.rdatatype.from_text(tok.get_string())
        scheme = Scheme.make(tok.get_string())
        port = tok.get_uint16()
        target = tok.get_name(origin, relativize, relativize_to)
        return cls(rdclass, rdtype, rrtype, scheme, port, target)

    def _to_wire(self, file: IO[bytes], compress: dns.name.CompressType | None = None, origin: dns.name.Name | None = None, canonicalize: bool = False) -> None:
        three_ints = struct.pack("!HBH", self.rrtype, self.scheme, self.port)
        file.write(three_ints)
        self.target.to_wire(file, None, origin, False)

    @classmethod
    def from_wire_parser(cls, rdclass: dns.rdataclass.RdataClass, rdtype: dns.rdatatype.RdataType, parser: dns.wire.Parser, origin: dns.name.Name | None = None) -> Self:
        rrtype, scheme, port = parser.get_struct("!HBH")
        target = parser.get_name(origin)
        return cls(rdclass, rdtype, rrtype, scheme, port, target)
