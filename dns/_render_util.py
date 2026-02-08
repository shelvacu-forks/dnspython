import contextlib
import typing

import dns.exception


@contextlib.contextmanager
def prefixed_length(output: typing.IO[bytes], length_length: int) -> typing.Iterator[None]:
    output.write(b"\00" * length_length)
    start = output.tell()
    yield
    end = output.tell()
    length = end - start
    if length > 0:
        try:
            output.seek(start - length_length)
            try:
                output.write(length.to_bytes(length_length, "big"))
            except OverflowError:
                raise dns.exception.FormError
        finally:
            output.seek(end)
