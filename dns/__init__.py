# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2007, 2009, 2011 Nominum, Inc.
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

"""dnspython DNS toolkit"""
from . import asyncbackend
from . import asyncquery
from . import asyncresolver
from . import btree
from . import btreezone
from . import dnssec
from . import dnssecalgs
from . import dnssectypes
from . import e164
from . import edns
from . import entropy
from . import exception
from . import flags
from . import immutable
from . import inet
from . import ipv4
from . import ipv6
from . import message
from . import name
from . import namedict
from . import node
from . import opcode
from . import query
from . import quic
from . import rcode
from . import rdata
from . import rdataclass
from . import rdataset
from . import rdatatype
from . import renderer
from . import resolver
from . import reversename
from . import rrset
from . import serial
from . import set
from . import tokenizer
from . import transaction
from . import tsig
from . import tsigkeyring
from . import ttl
from . import rdtypes
from . import update
from . import version
from . import versioned
from . import wire
from . import wirebase
from . import xfr
from . import zone
from . import zonetypes
from . import zonefile

__all__ = [
    "asyncbackend",
    "asyncquery",
    "asyncresolver",
    "btree",
    "btreezone",
    "dnssec",
    "dnssecalgs",
    "dnssectypes",
    "e164",
    "edns",
    "entropy",
    "exception",
    "flags",
    "immutable",
    "inet",
    "ipv4",
    "ipv6",
    "message",
    "name",
    "namedict",
    "node",
    "opcode",
    "query",
    "quic",
    "rcode",
    "rdata",
    "rdataclass",
    "rdataset",
    "rdatatype",
    "renderer",
    "resolver",
    "reversename",
    "rrset",
    "serial",
    "set",
    "tokenizer",
    "transaction",
    "tsig",
    "tsigkeyring",
    "ttl",
    "rdtypes",
    "update",
    "version",
    "versioned",
    "wire",
    "wirebase",
    "xfr",
    "zone",
    "zonetypes",
    "zonefile",
]

from dns.version import version as __version__  # noqa
