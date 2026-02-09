# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2001-2017 Nominum, Inc.
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

"""Help for building DNS wire format messages"""

import contextlib
import io
import random
import struct
import time
from collections.abc import Sequence, Iterator
from typing import Literal, Any

import dns.edns
import dns.exception
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.OPT
import dns.rdtypes.ANY.TSIG
import dns.rrset
import dns.tsig
from dns._render_util import prefixed_length as prefixed_length  # pyright: ignore

DEFAULT_EDNS_PAYLOAD = 1232

QUESTION = 0
ANSWER = 1
AUTHORITY = 2
ADDITIONAL = 3

type SectionInt = Literal[0, 1, 2, 3]


def _make_opt(
    flags: int = 0,
    payload: int = DEFAULT_EDNS_PAYLOAD,
    options: Sequence[dns.edns.Option] | None = None,
) -> dns.rrset.RRset:
    opt = dns.rdtypes.ANY.OPT.OPT(payload, dns.rdatatype.OPT, options or ())
    return dns.rrset.from_rdata(dns.name.root, int(flags), opt)


def _make_tsig(
    keyname: str | dns.name.Name | None,
    algorithm: dns.tsig.ToAlgorithm,
    time_signed: int,
    fudge: int,
    mac: bytearray | bytes,
    original_id: int,
    error: dns.rcode.Rcode | int,
    other: bytearray | bytes,
) -> dns.rrset.RRset:
    tsig = dns.rdtypes.ANY.TSIG.TSIG(
        dns.rdataclass.ANY,
        dns.rdatatype.TSIG,
        algorithm,
        time_signed,
        fudge,
        mac,
        original_id,
        error,
        other,
    )
    return dns.rrset.from_rdata(keyname, 0, tsig)


class Renderer:
    """Helper class for building DNS wire-format messages.

    Most applications can use the higher-level L{dns.message.Message}
    class and its to_wire() method to generate wire-format messages.
    This class is for those applications which need finer control
    over the generation of messages.

    Typical use::

        r = dns.renderer.Renderer(id=1, flags=0x80, max_size=512)
        r.add_question(qname, qtype, qclass)
        r.add_rrset(dns.renderer.ANSWER, rrset_1)
        r.add_rrset(dns.renderer.ANSWER, rrset_2)
        r.add_rrset(dns.renderer.AUTHORITY, ns_rrset)
        r.add_rrset(dns.renderer.ADDITIONAL, ad_rrset_1)
        r.add_rrset(dns.renderer.ADDITIONAL, ad_rrset_2)
        r.add_edns(0, 0, 4096)
        r.write_header()
        r.add_tsig(keyname, secret, 300, 1, 0, '', request_mac)
        wire = r.get_wire()

    If padding is going to be used, then the OPT record MUST be
    written after everything else in the additional section except for
    the TSIG (if any).

    output, an io.BytesIO, where rendering is written

    id: the message id

    flags: the message flags

    max_size: the maximum size of the message

    origin: the origin to use when rendering relative names

    compress: the compression table

    section: an int, the section currently being rendered

    counts: list of the number of RRs in each section

    mac: the MAC of the rendered message (if TSIG was used)
    """

    id: int
    flags: int
    max_size: int
    origin: dns.name.Name | None
    compress: dns.name.CompressType
    section: SectionInt
    counts: list[int]
    output: io.BytesIO
    mac: str
    reserved: int
    was_padded: bool

    def __init__(
        self,
        id: int | None = None,
        flags: int = 0,
        max_size: int = 65535,
        origin: dns.name.Name | None = None,
    ) -> None:
        """Initialize a new renderer."""

        self.output = io.BytesIO()
        if id is None:
            self.id = random.randint(0, 65535)
        else:
            self.id = id
        self.flags = flags
        self.max_size = max_size
        self.origin = origin
        self.compress = {}
        self.section = QUESTION
        self.counts = [0, 0, 0, 0]
        self.output.write(b"\x00" * 12)
        self.mac = ""
        self.reserved = 0
        self.was_padded = False

    def _rollback(self, where: int) -> None:
        """Truncate the output buffer at offset *where*, and remove any
        compression table entries that pointed beyond the truncation
        point.
        """

        self.output.seek(where)
        self.output.truncate()
        keys_to_delete: list[dns.name.Name] = []
        for k, v in self.compress.items():
            if v >= where:
                keys_to_delete.append(k)
        for k in keys_to_delete:
            del self.compress[k]

    def _set_section(self, section: SectionInt):
        """Set the renderer's current section.

        Sections must be rendered order: QUESTION, ANSWER, AUTHORITY,
        ADDITIONAL.  Sections may be empty.

        Raises dns.exception.FormError if an attempt was made to set
        a section value less than the current section.
        """

        if self.section != section:
            if self.section > section:
                raise dns.exception.FormError
            self.section = section

    @contextlib.contextmanager
    def _track_size(self) -> Iterator[int]:
        start = self.output.tell()
        yield start
        if self.output.tell() > self.max_size:
            self._rollback(start)
            raise dns.exception.TooBig

    @contextlib.contextmanager
    def _temporarily_seek_to(self, where: int) -> Iterator[None]:
        current = self.output.tell()
        try:
            self.output.seek(where)
            yield
        finally:
            self.output.seek(current)

    def add_question(
        self,
        qname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        rdclass: dns.rdataclass.RdataClass = dns.rdataclass.IN,
    ) -> None:
        """Add a question to the message."""

        self._set_section(QUESTION)
        with self._track_size():
            qname.to_wire(self.output, self.compress, self.origin)
            self.output.write(struct.pack("!HH", rdtype, rdclass))
        self.counts[QUESTION] += 1

    def add_rrset(
        self,
        section: SectionInt,
        rrset: dns.rrset.RRset,
        **kw: Any,
    ) -> None:
        """Add the rrset to the specified section.

        Any keyword arguments are passed on to the rdataset's to_wire()
        routine.
        """

        self._set_section(section)
        with self._track_size():
            n = rrset.to_wire(file=self.output, compress=self.compress, origin=self.origin, **kw)
        self.counts[section] += n

    def add_rdataset(
        self,
        section: SectionInt,
        name: dns.name.Name,
        rdataset: dns.rdataset.Rdataset,
        **kw: Any,
    ):
        """Add the rdataset to the specified section, using the specified
        name as the owner name.

        Any keyword arguments are passed on to the rdataset's to_wire()
        routine.
        """

        self._set_section(section)
        with self._track_size():
            n = rdataset.to_wire(name=name, file=self.output, compress=self.compress, origin=self.origin, **kw)
        self.counts[section] += n

    def add_opt(
        self,
        opt: dns.rrset.RRset,
        pad: int = 0,
        opt_size: int = 0,
        tsig_size: int = 0,
    ) -> None:
        """Add *opt* to the additional section, applying padding if desired.  The
        padding will take the specified precomputed OPT size and TSIG size into
        account.

        Note that we don't have reliable way of knowing how big a GSS-TSIG digest
        might be, so we we might not get an even multiple of the pad in that case."""
        if pad:
            ttl = opt.ttl
            assert opt_size >= 11
            opt_rdata = opt[0]
            assert isinstance(opt_rdata, dns.rdtypes.ANY.OPT.OPT)
            size_without_padding = self.output.tell() + opt_size + tsig_size
            remainder = size_without_padding % pad
            pad_b: bytes
            if remainder:
                pad_b = b"\x00" * (pad - remainder)
            else:
                pad_b = b""
            options = list(opt_rdata.options)
            options.append(dns.edns.GenericOption(dns.edns.OptionType.PADDING, pad_b))
            opt = _make_opt(ttl, opt_rdata.rdclass, options)  # pyright: ignore
            self.was_padded = True
        self.add_rrset(ADDITIONAL, opt)

    def add_edns(
        self,
        edns: int,
        ednsflags: int,
        payload: int,
        options: Sequence[dns.edns.Option] | None = None,
    ) -> None:
        """Add an EDNS OPT record to the message."""

        # make sure the EDNS version in ednsflags agrees with edns
        ednsflags &= 0xFF00FFFF
        ednsflags |= edns << 16
        opt = _make_opt(ednsflags, payload, options)  # pyright: ignore
        self.add_opt(opt)

    def add_tsig(
        self,
        keyname: dns.name.Name,
        secret: dns.tsig.Key,
        fudge: int,
        id: int,
        tsig_error: dns.rcode.Rcode | int,
        other_data: bytearray | bytes,
        request_mac: bytearray | bytes,
        algorithm: dns.tsig.ToAlgorithm = dns.tsig.default_algorithm,
    ) -> None:
        """Add a TSIG signature to the message."""

        s = self.output.getvalue()

        key = secret
        tsig_set = _make_tsig(
            keyname, algorithm, 0, fudge, b"", id, tsig_error, other_data
        )
        tsig_0 = tsig_set[0]
        assert isinstance(tsig_0, dns.rdtypes.ANY.TSIG.TSIG)
        tsig_rd, _ = key.sign(s, tsig_0, int(time.time()), request_mac)
        self._write_tsig(tsig_rd, keyname)

    def add_multi_tsig[C: dns.tsig.AnyContext](
        self,
        ctx: C,
        keyname: dns.name.Name,
        secret: dns.tsig.KeyBase[C],
        fudge: int,
        id: int,
        tsig_error: dns.rcode.Rcode | int,
        other_data: bytearray | bytes,
        request_mac: bytearray | bytes,
    ) -> C:
        """Add a TSIG signature to the message. Unlike add_tsig(), this can be
        used for a series of consecutive DNS envelopes, e.g. for a zone
        transfer over TCP [RFC2845, 4.4].

        For the first message in the sequence, give ctx=None. For each
        subsequent message, give the ctx that was returned from the
        add_multi_tsig() call for the previous message."""

        s = self.output.getvalue()

        key = secret
        tsig_set = _make_tsig(
            keyname, key.algorithm, 0, fudge, b"", id, tsig_error, other_data
        )
        tsig_0 = tsig_set[0]
        assert isinstance(tsig_0, dns.rdtypes.ANY.TSIG.TSIG)
        tsig, ctx = key.sign(
            s, tsig_0, int(time.time()), request_mac, ctx, True
        )
        self._write_tsig(tsig, keyname)
        return ctx

    def _write_tsig(
        self,
        tsig: dns.rdtypes.ANY.TSIG.TSIG,
        keyname: dns.name.Name,
    ) -> None:
        if self.was_padded:
            compress = None
        else:
            compress = self.compress
        self._set_section(ADDITIONAL)
        with self._track_size():
            keyname.to_wire(self.output, compress, self.origin)
            self.output.write(
                struct.pack("!HHI", dns.rdatatype.TSIG, dns.rdataclass.ANY, 0)
            )
            with prefixed_length(self.output, 2):
                tsig.to_wire(self.output)

        self.counts[ADDITIONAL] += 1
        with self._temporarily_seek_to(10):
            self.output.write(struct.pack("!H", self.counts[ADDITIONAL]))

    def write_header(self):
        """Write the DNS message header.

        Writing the DNS message header is done after all sections
        have been rendered, but before the optional TSIG signature
        is added.
        """

        with self._temporarily_seek_to(0):
            self.output.write(
                struct.pack(
                    "!HHHHHH",
                    self.id,
                    self.flags,
                    self.counts[0],
                    self.counts[1],
                    self.counts[2],
                    self.counts[3],
                )
            )

    def get_wire(self):
        """Return the wire format message."""

        return self.output.getvalue()

    def reserve(self, size: int) -> None:
        """Reserve *size* bytes."""
        if size < 0:
            raise ValueError("reserved amount must be non-negative")
        if size > self.max_size:
            raise ValueError("cannot reserve more than the maximum size")
        self.reserved += size
        self.max_size -= size

    def release_reserved(self) -> None:
        """Release the reserved bytes."""
        self.max_size += self.reserved
        self.reserved = 0
