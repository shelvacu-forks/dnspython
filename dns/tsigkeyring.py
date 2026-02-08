# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
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

"""A place to store TSIG keys."""

import base64
from collections.abc import Callable
import typing

import dns.name
import dns.tsig
import dns.message


type Textring = dict[str, str | tuple[str | dns.name.Name, bytes | str | dns.tsig.SecurityContext]]
type Keyring = dict[dns.name.Name, dns.tsig.Key | bytes]


type KeyringLike = dns.tsigkeyring.Keyring | dns.tsig.Key | Callable[[dns.message.Message, dns.name.Name], dns.tsig.Key] | None | typing.Literal[True]

def get_key(keyring: KeyringLike, keyname: dns.name.Name | str | None, message: dns.message.Message, default_algorithm: dns.tsig.AlgorithmHMAC) -> dns.tsig.Key | None:
    if isinstance(keyname, str):
        keyname = dns.name.from_text(keyname)
    if keyring is None or keyring is True:
        return None
    if callable(keyring):
        if keyname is None:
            return None
        return keyring(message, keyname)
    if isinstance(keyring, dict):
        if keyname is None:
            try:
                item = next(iter(keyring.items()))
            except StopIteration:
                return None
            keyname, v = item
        else:
            v = keyring.get(keyname)
        if isinstance(v, bytes):
            return dns.tsig.KeyHMAC(keyname, v, default_algorithm)
        else:
            return v
    return keyring
    

def from_text(textring: Textring) -> Keyring:
    """Convert a dictionary containing (textual DNS name, base64 secret)
    pairs into a binary keyring which has (dns.name.Name, bytes) pairs, or
    a dictionary containing (textual DNS name, (algorithm, base64 secret))
    pairs into a binary keyring which has (dns.name.Name, dns.tsig.Key) pairs.
    @rtype: dict"""

    keyring: Keyring = {}
    for name, value in textring.items():
        kname = dns.name.from_text(name)
        if isinstance(value, str):
            key = dns.tsig.KeyHMAC(kname, value)
            assert isinstance(key.secret, bytes)
            keyring[kname] = key.secret
        else:
            algorithm, secret = value
            keyring[kname] = dns.tsig.make_key(kname, secret, algorithm)
    return keyring


def to_text(keyring: Keyring) -> Textring:
    """Convert a dictionary containing (dns.name.Name, dns.tsig.Key) pairs
    into a text keyring which has (textual DNS name, (textual algorithm,
    base64 secret)) pairs, or a dictionary containing (dns.name.Name, bytes)
    pairs into a text keyring which has (textual DNS name, base64 secret) pairs.
    @rtype: dict"""

    textring:Textring = {}

    def b64encode(secret: bytes) -> str:
        return base64.encodebytes(secret).decode().rstrip()

    for name, key in keyring.items():
        tname = name.to_text()
        if isinstance(key, bytes):
            textring[tname] = b64encode(key)
        else:
            if isinstance(key.secret, bytes):
                text_secret = b64encode(key.secret)
            else:
                text_secret = str(key.secret)

            textring[tname] = (key.algorithm.value.to_text(), text_secret)
    return textring
