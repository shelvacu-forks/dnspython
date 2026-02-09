# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Serial Number Arthimetic from RFC 1982"""

from typing import Any, overload, TypeIs, Self, Literal


class Serial[Bits: int = int]:
    value: int
    bits: Bits

    __slots__ = ("value", "bits")

    @overload
    def __init__(self, value: int, bits: Bits) -> None: ...
    @overload
    def __init__(self: "Serial[Literal[32]]", value: int) -> None: ...
    def __init__(self: "Serial[int]", value: int, bits: int = 32):
        self.value = value % 2**bits
        self.bits = bits

    def new_with_same_bits(self, value: int) -> Self:
        return type(self)(value, self.bits)

    def __repr__(self):
        return f"dns.serial.Serial({self.value}, {self.bits})"

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, int):
            other = Serial(other, self.bits)
        elif not is_serial(other) or other.bits != self.bits:
            return NotImplemented
        return self.value == other.value

    def __ne__(self, other: Any) -> bool:
        if isinstance(other, int):
            other = Serial(other, self.bits)
        elif not is_serial(other) or other.bits != self.bits:
            return NotImplemented
        return self.value != other.value

    def __lt__(self, other_arg: Self | int) -> bool:
        if isinstance(other_arg, int):
            other = Serial(other_arg, self.bits)
        else:
            other = other_arg
        if not is_serial(other) or other.bits != self.bits:
            return NotImplemented
        if self.value < other.value and other.value - self.value < 2 ** (self.bits - 1):
            return True
        elif self.value > other.value and self.value - other.value > 2 ** (
            self.bits - 1
        ):
            return True
        else:
            return False

    def __le__(self, other: Self | int) -> bool:
        return self == other or self < other

    def __gt__(self, other_arg: Self | int) -> bool:
        if isinstance(other_arg, int):
            other = Serial(other_arg, self.bits)
        else:
            other = other_arg
        if not isinstance(other, Serial) or other.bits != self.bits:
            return NotImplemented
        if self.value < other.value and other.value - self.value > 2 ** (self.bits - 1):
            return True
        elif self.value > other.value and self.value - other.value < 2 ** (
            self.bits - 1
        ):
            return True
        else:
            return False

    def __ge__(self, other: Self | int) -> bool:
        return self == other or self > other

    def __add__(self, other: Self | int) -> Self:
        v = self.value
        if is_serial(other):
            delta = other.value
        elif isinstance(other, int):
            delta = other
        else:
            raise ValueError
        if abs(delta) > (2 ** (self.bits - 1) - 1):
            raise ValueError
        v += delta
        v = v % 2**self.bits
        return self.new_with_same_bits(v)

    def __iadd__(self, other: Self | int) -> Self:
        v = self.value
        if is_serial(other):
            delta = other.value
        elif isinstance(other, int):
            delta = other
        else:
            raise ValueError
        if abs(delta) > (2 ** (self.bits - 1) - 1):
            raise ValueError
        v += delta
        v = v % 2**self.bits
        self.value = v
        return self

    def __sub__(self, other: Self | int) -> Self:
        v = self.value
        if is_serial(other):
            delta = other.value
        elif isinstance(other, int):
            delta = other
        else:
            raise ValueError
        if abs(delta) > (2 ** (self.bits - 1) - 1):
            raise ValueError
        v -= delta
        v = v % 2**self.bits
        return self.new_with_same_bits(v)

    def __isub__(self, other: Self | int) -> Self:
        v = self.value
        if is_serial(other):
            delta = other.value
        elif isinstance(other, int):
            delta = other
        else:
            raise ValueError
        if abs(delta) > (2 ** (self.bits - 1) - 1):
            raise ValueError
        v -= delta
        v = v % 2**self.bits
        self.value = v
        return self

def is_serial(obj: Any) -> TypeIs[Serial[int]]:
    return isinstance(obj, Serial)
