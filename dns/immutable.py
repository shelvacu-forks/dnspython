# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from collections.abc import MutableMapping, Mapping, Collection
from typing import Any, Callable, Iterator, Iterable, overload, TypeIs, TypeGuard, Literal

from dns._immutable_ctx import immutable as immutable  # export


@immutable
class Dict[K, V](Mapping[K, V]):  # lgtm[py/missing-equals]
    _odict: Mapping[K, V]

    @overload
    def __init__(self, dictionary: Mapping[K, V], no_copy: Literal[True]) -> None: ...
    @overload
    def __init__(
        self,
        dictionary: Iterable[tuple[K, V]],
        no_copy: Literal[False] = False,
        map_factory: Callable[[], MutableMapping[K, V]] = dict,
    ) -> None: ...
    def __init__(
        self,
        dictionary: Any,
        no_copy: bool = False,
        map_factory: Callable[[], MutableMapping[K, V]] = dict,
    ) -> None:
        """Make an immutable dictionary from the specified dictionary.

        If *no_copy* is `True`, then *dictionary* will be wrapped instead
        of copied.  Only set this if you are sure there will be no external
        references to the dictionary.
        """
        if no_copy and isinstance(dictionary, Mapping):
            self._odict = dictionary
        else:
            self._odict = map_factory()
            self._odict.update(dictionary)
        self._hash = None

    def __getitem__(self, key: K) -> V:
        return self._odict.__getitem__(key)

    def __hash__(self) -> int:
        if self._hash is None:
            h = 0
            for key in sorted(self._odict.keys()): # type: ignore
                h ^= hash(key) # type: ignore
            object.__setattr__(self, "_hash", h)
            return h
        else:
            return self._hash

    def __len__(self) -> int:
        return len(self._odict)

    def __iter__(self) -> Iterator[K]:
        return iter(self._odict)


def is_a_tuple(o: Any) -> TypeIs[tuple[Any, ...]]:
    return isinstance(o, tuple)

def is_a_list(o: Any) -> TypeGuard[Collection[Any]]:
    return isinstance(o, list)

def is_a_dict(o: Any) -> TypeGuard[Mapping[Any, Any]]:
    return isinstance(o, dict)


@overload
def constify(o: bytearray) -> bytes: ...
@overload
def constify[T: tuple[Any, ...]](o: T) -> T: ...
@overload
def constify[T](o: list[T]) -> tuple[T, ...]: ...
@overload
def constify[K, V](o: dict[K, V]) -> Dict[K, V]: ...
@overload
def constify(o: Any) -> Any: ...
def constify(o: Any) -> Any:
    """
    Convert mutable types to immutable types.
    """
    if isinstance(o, bytearray):
        return bytes(o)
    if is_a_tuple(o):
        try:
            hash(o)
            return o
        except Exception:
            return tuple(constify(elt) for elt in o) # type: ignore[reportUnknownVariableType]
    if is_a_list(o):
        return tuple(constify(elt) for elt in o) # type: ignore[reportUnknownVariableType]
    if is_a_dict(o):
        cdict:dict[Any, Any] = dict()
        for k, v in o.items():
            cdict[k] = constify(v)
        return Dict(cdict, True)
    return o
