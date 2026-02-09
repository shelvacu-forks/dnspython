# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license
#
# Support for Discovery of Designated Resolvers

import socket
import time
from collections.abc import Iterable
from typing import Protocol, Literal, TypeAlias
from urllib.parse import urlparse

import dns.asyncbackend
import dns.inet
import dns.name
import dns.nameserver
import dns.query
import dns.rdtypes.svcbbase
import dns.resolver
import dns.rdtypes.IN.SVCB

# The special name of the local resolver when using DDR
_local_resolver_name = dns.name.from_text("_dns.resolver.arpa")


#
# Processing is split up into I/O independent and I/O dependent parts to
# make supporting sync and async versions easy.
#


class _SVCBInfo:
    def __init__(
        self,
        bootstrap_address: str,
        port: int,
        hostname: str,
        nameservers: list[dns.nameserver.Nameserver],
    ) -> None:
        self.bootstrap_address = bootstrap_address
        self.port = port
        self.hostname = hostname
        self.nameservers = nameservers

    def ddr_check_certificate(self, cert: dns.asyncbackend.PeerCertDict) -> bool:
        """Verify that the _SVCBInfo's address is in the cert's subjectAltName (SAN)"""
        for thing in cert["subjectAltName"]:
            assert isinstance(thing, tuple)
            assert isinstance(thing[0], str)
            name, value = thing
            if name == "IP Address" and value == self.bootstrap_address:
                return True
        return False

    def make_tls_context(self) -> dns.query.ssl.SSLContext:
        ssl = dns.query.ssl
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def ddr_tls_check_sync(self, lifetime: float) -> bool:
        ctx = self.make_tls_context()
        expiration = time.time() + lifetime
        with socket.create_connection(
            (self.bootstrap_address, self.port), lifetime
        ) as s:
            with ctx.wrap_socket(s, server_hostname=self.hostname) as ts:
                ts.settimeout(dns.query._remaining(expiration))
                ts.do_handshake()
                cert = ts.getpeercert()
                assert cert is not None
                return self.ddr_check_certificate(cert)

    async def ddr_tls_check_async(
        self,
        lifetime: float,
        backend: dns.asyncbackend.Backend | None = None,
    ) -> bool:
        if backend is None:
            backend = dns.asyncbackend.get_default_backend()
        ctx = self.make_tls_context()
        expiration = time.time() + lifetime
        async with await backend.make_socket(
            dns.inet.af_for_address(self.bootstrap_address),
            socket.SOCK_STREAM,
            0,
            None,
            (self.bootstrap_address, self.port),
            lifetime,
            ctx,
            self.hostname,
        ) as ts:
            cert = await ts.getpeercert(dns.query._remaining(expiration))
            return self.ddr_check_certificate(cert)


def _extract_nameservers_from_svcb(answer: dns.resolver.Answer) -> list[_SVCBInfo]:
    bootstrap_address = answer.nameserver
    if not dns.inet.is_address(bootstrap_address):
        return []
    infos:list[_SVCBInfo] = []
    assert answer.rrset is not None
    for rr in answer.rrset.processing_order():
        assert isinstance(rr, dns.rdtypes.IN.SVCB.SVCB)
        nameservers = []
        param = rr.params.get(dns.rdtypes.svcbbase.ParamKey.ALPN)
        if param is None:
            continue
        alpns = set(param.ids)
        host = rr.target.to_text(omit_final_dot=True)
        port = None
        param = rr.params.get(dns.rdtypes.svcbbase.ParamKey.PORT)
        if param is not None:
            port = param.port
        # For now we ignore address hints and address resolution and always use the
        # bootstrap address
        if b"h2" in alpns:
            param = rr.params.get(dns.rdtypes.svcbbase.ParamKey.DOHPATH)
            if param is None or not param.value.endswith(b"{?dns}"):
                continue
            path = param.value[:-6].decode()
            if not path.startswith("/"):
                path = "/" + path
            if port is None:
                port = 443
            url = f"https://{host}:{port}{path}"
            # check the URL
            try:
                urlparse(url)
                nameservers.append(dns.nameserver.DoHNameserver(url, bootstrap_address))
            except Exception:
                # continue processing other ALPN types
                pass
        if b"dot" in alpns:
            if port is None:
                port = 853
            nameservers.append(
                dns.nameserver.DoTNameserver(bootstrap_address, port, host)
            )
        if b"doq" in alpns:
            if port is None:
                port = 853
            nameservers.append(
                dns.nameserver.DoQNameserver(bootstrap_address, port, True, host)
            )
        if len(nameservers) > 0:
            infos.append(_SVCBInfo(bootstrap_address, port, host, nameservers))
    return infos


def _get_nameservers_sync(answer: dns.resolver.Answer, lifetime: float) -> list[dns.nameserver.Nameserver]: # type: ignore[reportUnusedFunction]
    """Return a list of TLS-validated resolver nameservers extracted from an SVCB
    answer."""
    nameservers:list[dns.nameserver.Nameserver] = []
    infos = _extract_nameservers_from_svcb(answer)
    for info in infos:
        try:
            if info.ddr_tls_check_sync(lifetime):
                nameservers.extend(info.nameservers)
        except Exception:
            pass
    return nameservers


async def _get_nameservers_async(answer: dns.resolver.Answer, lifetime: float) -> list[dns.nameserver.Nameserver]: # type: ignore[reportUnusedFunction]
    """Return a list of TLS-validated resolver nameservers extracted from an SVCB
    answer."""
    nameservers:list[dns.nameserver.Nameserver] = []
    infos = _extract_nameservers_from_svcb(answer)
    for info in infos:
        try:
            if await info.ddr_tls_check_async(lifetime):
                nameservers.extend(info.nameservers)
        except Exception:
            pass
    return nameservers
