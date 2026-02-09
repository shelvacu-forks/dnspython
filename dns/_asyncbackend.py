# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import ssl
from typing import overload, Any, Literal, Self

# This is a nullcontext for both sync and async.  3.7 has a nullcontext,
# but it is only for sync use.


class NullContext[T]:
    @overload
    def __init__(self, enter_result: T) -> None: ...
    @overload
    def __init__[V](self: "NullContext[V | None]", enter_result: V | None = None) -> None: ...
    def __init__(self: "NullContext[Any]", enter_result:Any=None):
        self.enter_result = enter_result

    def __enter__(self) -> T:
        return self.enter_result

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> Literal[False]:
        return False

    async def __aenter__(self) -> T:
        return self.enter_result

    async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> Literal[False]:
        return False


type _PCTRTT = tuple[tuple[str, str], ...]
type _PCTRTTT = tuple[_PCTRTT, ...]
type PeerCertDict = dict[str, str | _PCTRTT | _PCTRTTT]
type _RetAddress = Any # this is exactly what typeshed does :'(

# These are declared here so backends can import them without creating
# circular dependencies with dns.asyncbackend.

class Socket:  # pragma: no cover
    def __init__(self, family: int, type: int):
        self.family = family
        self.type = type

    async def close(self) -> None:
        pass

    async def getpeername(self) -> _RetAddress:
        raise NotImplementedError

    async def getsockname(self) -> _RetAddress:
        raise NotImplementedError

    async def getpeercert(self, timeout: float) -> PeerCertDict:
        raise NotImplementedError

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> Literal[False]:
        await self.close()
        return False


class DatagramSocket(Socket):  # pragma: no cover
    async def sendto(self, what, destination, timeout: float):
        raise NotImplementedError

    async def recvfrom(self, size: int, timeout: float):
        raise NotImplementedError


class StreamSocket(Socket):  # pragma: no cover
    async def sendall(self, what, timeout: float):
        raise NotImplementedError

    async def recv(self, size: int, timeout: float):
        raise NotImplementedError


class NullTransport:
    async def connect_tcp(self, host, port, timeout, local_address):
        raise NotImplementedError


class Backend:  # pragma: no cover
    def name(self) -> str:
        return "unknown"

    async def make_socket(
        self,
        af: int,
        socktype: int,
        proto: int =0,
        source: str | None = None,
        destination: tuple[str, int] | None = None,
        timeout: float | None = None,
        ssl_context: ssl.SSLContext | None = None,
        server_hostname: str | None = None,
    ) -> Socket:
        raise NotImplementedError

    def datagram_connection_required(self):
        return False

    async def sleep(self, interval):
        raise NotImplementedError

    def get_transport_class(self):
        raise NotImplementedError

    async def wait_for(self, awaitable, timeout):
        raise NotImplementedError
