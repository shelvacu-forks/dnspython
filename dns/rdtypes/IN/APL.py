# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2017 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import binascii
import codecs
import struct
import ipaddress
from collections.abc import Sequence
from typing import Any, IO, Self

import dns.immutable
import dns.ipv4
import dns.ipv6
import dns.rdata
import dns.tokenizer


@dns.immutable.immutable
class APLItem:
    """An APL list item."""

    __slots__ = ["family", "negation", "address", "prefix"]
    family: int
    negation: bool
    address: str | bytes
    prefix: int

    def __init__(
        self,
        family: int,
        negation: bool,
        address: str | bytes | ipaddress.IPv4Address | ipaddress.IPv6Address,
        prefix: int,
    ) -> None:
        self.family = dns.rdata.Rdata._as_uint16(family)
        self.negation = dns.rdata.Rdata._as_bool(negation)
        if self.family == 1:
            assert not isinstance(address, ipaddress.IPv6Address)
            self.address = dns.rdata.Rdata._as_ipv4_address(address)
            self.prefix = dns.rdata.Rdata._as_int(prefix, 0, 32)
        elif self.family == 2:
            assert not isinstance(address, ipaddress.IPv4Address)
            self.address = dns.rdata.Rdata._as_ipv6_address(address)
            self.prefix = dns.rdata.Rdata._as_int(prefix, 0, 128)
        else:
            self.address = dns.rdata.Rdata._as_bytes(address, max_length=127)
            self.prefix = dns.rdata.Rdata._as_uint8(prefix)

    def __str__(self):
        if self.negation:
            return f"!{self.family}:{self.address}/{self.prefix}"
        else:
            return f"{self.family}:{self.address}/{self.prefix}"

    def to_wire(self, file: IO[bytes]) -> None:
        if self.family == 1:
            address = dns.ipv4.inet_aton(self.address)
        elif self.family == 2:
            address = dns.ipv6.inet_aton(self.address)
        else:
            address = binascii.unhexlify(self.address)
        #
        # Truncate least significant zero bytes.
        #
        last = 0
        for i in range(len(address) - 1, -1, -1):
            if address[i] != 0:
                last = i + 1
                break
        address = address[0:last]
        l = len(address)
        assert l < 128
        if self.negation:
            l |= 0x80
        header = struct.pack("!HBB", self.family, self.prefix, l)
        file.write(header)
        file.write(address)


@dns.immutable.immutable
class APL(dns.rdata.Rdata):
    """APL record."""

    # see: RFC 3123

    __slots__ = ["items"]
    items: tuple[APLItem, ...]

    def __init__(self, rdclass: dns.rdataclass.RdataClass, rdtype: dns.rdatatype.RdataType, items: Sequence[APLItem]):
        super().__init__(rdclass, rdtype)
        for item in items:
            if not isinstance(item, APLItem):
                raise ValueError("item not an APLItem")
        self.items = tuple(items)

    def to_text(self, origin: dns.name.Name | None = None, relativize: bool = True, **kw: Any) -> str:
        return " ".join(map(str, self.items))

    @classmethod
    def from_text(
        cls, rdclass: dns.rdataclass.RdataClass, rdtype: dns.rdatatype.RdataType, tok: dns.tokenizer.Tokenizer, origin: dns.name.Name | None = None, relativize: bool = True, relativize_to: dns.name.Name | None = None
    ):
        items:list[APLItem] = []
        for token in tok.get_remaining():
            item = token.unescape().value
            if item[0] == "!":
                negation = True
                item = item[1:]
            else:
                negation = False
            family, rest = item.split(":", 1)
            family = int(family)
            address, prefix = rest.split("/", 1)
            prefix = int(prefix)
            item = APLItem(family, negation, address, prefix)
            items.append(item)

        return cls(rdclass, rdtype, items)

    def _to_wire(self, file: IO[bytes], compress: dns.name.CompressType | None = None, origin: dns.name.Name | None = None, canonicalize: bool = False) -> None:
        for item in self.items:
            item.to_wire(file)

    @classmethod
    def from_wire_parser(cls, rdclass: dns.rdataclass.RdataClass, rdtype: dns.rdatatype.RdataType, parser: dns.wire.Parser, origin: dns.name.Name | None = None) -> Self:
        items:list[APLItem] = []
        while parser.remaining() > 0:
            header = parser.get_struct("!HBB")
            afdlen = header[2]
            if afdlen > 127:
                negation = True
                afdlen -= 128
            else:
                negation = False
            address = parser.get_bytes(afdlen)
            l = len(address)
            if header[0] == 1:
                if l < 4:
                    address += b"\x00" * (4 - l)
            elif header[0] == 2:
                if l < 16:
                    address += b"\x00" * (16 - l)
            else:
                #
                # This isn't really right according to the RFC, but it
                # seems better than throwing an exception
                #
                address = codecs.encode(address, "hex_codec")
            item = APLItem(header[0], negation, address, header[1])
            items.append(item)
        return cls(rdclass, rdtype, items)
