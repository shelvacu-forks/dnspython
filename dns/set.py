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

import itertools
from collections.abc import MutableMapping
from typing import Iterator, Iterable, Self, Any, overload


class Set[T]:
    """A simple set class.

    This class was originally used to deal with python not having a set class, and
    originally the class used lists in its implementation.  The ordered and indexable
    nature of RRsets and Rdatasets is unfortunately widely used in dnspython
    applications, so for backwards compatibility sets continue to be a custom class, now
    based on an ordered dictionary.
    """

    __slots__ = ["items"]
    items:MutableMapping[T, None]

    def __init__(self, items:Iterable[T]|None=None):
        """Initialize the set.

        *items*, an iterable or ``None``, the initial set of items.
        """

        self.items = dict()
        if items is not None:
            for item in items:
                # This is safe for how we use set, but if other code
                # subclasses it could be a legitimate issue.
                self.add(item)  # lgtm[py/init-calls-subclass]

    def __repr__(self) -> str:
        return f"dns.set.Set({repr(list(self.items.keys()))})"  # pragma: no cover

    def add(self, item: T) -> None:
        """Add an item to the set."""

        if item not in self.items:
            self.items[item] = None

    def remove(self, item: T) -> None:
        """Remove an item from the set."""

        try:
            del self.items[item]
        except KeyError:
            raise ValueError

    def discard(self, item: T) -> None:
        """Remove an item from the set if present."""

        self.items.pop(item, None)

    def pop(self) -> T:
        """Remove an arbitrary item from the set."""
        k, _ = self.items.popitem()
        return k

    def _clone(self) -> Self:
        """Make a (shallow) copy of the set.

        There is a 'clone protocol' that subclasses of this class
        should use.  To make a copy, first call your super's _clone()
        method, and use the object returned as the new instance.  Then
        make shallow copies of the attributes defined in the subclass.

        This protocol allows us to write the set algorithms that
        return new instances (e.g. union) once, and keep using them in
        subclasses.
        """

        if hasattr(self, "_clone_class"):
            cls = self._clone_class  # pyright: ignore
        else:
            cls = self.__class__
        obj = cls.__new__(cls) # type: ignore
        obj.items = dict()
        obj.items.update(self.items)
        return obj # type: ignore

    def __copy__(self) -> Self:
        """Make a (shallow) copy of the set."""

        return self._clone()

    def copy(self) -> Self:
        """Make a (shallow) copy of the set."""

        return self._clone()

    def union_update(self, other: "Set[T]") -> None:
        """Update the set, adding any elements from other which are not
        already in the set.
        """

        if not isinstance(other, Set):
            raise ValueError("other must be a Set instance")
        if self is other:  # lgtm[py/comparison-using-is]
            return
        for item in other.items:
            self.add(item)

    def intersection_update(self, other: "Set[T]") -> None:
        """Update the set, removing any elements from other which are not
        in both sets.
        """

        if not isinstance(other, Set):
            raise ValueError("other must be a Set instance")
        if self is other:  # lgtm[py/comparison-using-is]
            return
        # we make a copy of the list so that we can remove items from
        # the list without breaking the iterator.
        for item in list(self.items):
            if item not in other.items:
                del self.items[item]

    def difference_update(self, other: "Set[T]") -> None:
        """Update the set, removing any elements from other which are in
        the set.
        """

        if not isinstance(other, Set):
            raise ValueError("other must be a Set instance")
        if self is other:  # lgtm[py/comparison-using-is]
            self.items.clear()
        else:
            for item in other.items:
                self.discard(item)

    def symmetric_difference_update(self, other: "Set[T]") -> None:
        """Update the set, retaining only elements unique to both sets."""

        if not isinstance(other, Set):
            raise ValueError("other must be a Set instance")
        if self is other:  # lgtm[py/comparison-using-is]
            self.items.clear()
        else:
            overlap = self.intersection(other)
            self.union_update(other)
            self.difference_update(overlap)

    def union(self, other: "Set[T]") -> Self:
        """Return a new set which is the union of ``self`` and ``other``.

        Returns the same Set type as this set.
        """

        obj = self._clone()
        obj.union_update(other)
        return obj

    def intersection(self, other: "Set[T]") -> Self:
        """Return a new set which is the intersection of ``self`` and
        ``other``.

        Returns the same Set type as this set.
        """

        obj = self._clone()
        obj.intersection_update(other)
        return obj

    def difference(self, other: "Set[T]") -> Self:
        """Return a new set which ``self`` - ``other``, i.e. the items
        in ``self`` which are not also in ``other``.

        Returns the same Set type as this set.
        """

        obj = self._clone()
        obj.difference_update(other)
        return obj

    def symmetric_difference(self, other: "Set[T]") -> Self:
        """Return a new set which (``self`` - ``other``) | (``other``
        - ``self), ie: the items in either ``self`` or ``other`` which
        are not contained in their intersection.

        Returns the same Set type as this set.
        """

        obj = self._clone()
        obj.symmetric_difference_update(other)
        return obj

    def __or__(self, other: "Set[T]") -> Self:
        return self.union(other)

    def __and__(self, other: "Set[T]") -> Self:
        return self.intersection(other)

    def __add__(self, other: "Set[T]") -> Self:
        return self.union(other)

    def __sub__(self, other: "Set[T]") -> Self:
        return self.difference(other)

    def __xor__(self, other: "Set[T]") -> Self:
        return self.symmetric_difference(other)

    def __ior__(self, other: "Set[T]") -> Self:
        self.union_update(other)
        return self

    def __iand__(self, other: "Set[T]") -> Self:
        self.intersection_update(other)
        return self

    def __iadd__(self, other: "Set[T]") -> Self:
        self.union_update(other)
        return self

    def __isub__(self, other: "Set[T]") -> Self:
        self.difference_update(other)
        return self

    def __ixor__(self, other: "Set[T]") -> Self:
        self.symmetric_difference_update(other)
        return self

    def update(self, other: "Set[T]") -> None:
        """Update the set, adding any elements from other which are not
        already in the set.

        *other*, the collection of items with which to update the set, which
        may be any iterable type.
        """

        for item in other:
            self.add(item)

    def clear(self) -> None:
        """Make the set empty."""
        self.items.clear()

    def __eq__(self, other:Any) -> bool:
        if not isinstance(other, Set):
            return False
        return self.items == other.items # type: ignore

    def __ne__(self, other:Any) -> bool:
        return not self.__eq__(other)

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self) -> Iterator[T]:
        return iter(self.items)

    @overload
    def __getitem__(self, i:int) -> T: ...
    @overload
    def __getitem__(self, i:slice[int]) -> Iterable[T]: ...
    def __getitem__(self, i:slice[int]|int) -> T|Iterable[T]:
        if isinstance(i, slice):
            return list(itertools.islice(self.items, i.start, i.stop, i.step))
        else:
            return next(itertools.islice(self.items, i, i + 1))

    def __delitem__(self, i:int|slice[int]) -> None:
        if isinstance(i, slice):
            for elt in list(self[i]):
                del self.items[elt]
        else:
            del self.items[self[i]]

    def issubset(self, other: "Set[T]") -> bool:
        """Is this set a subset of *other*?

        Returns a ``bool``.
        """

        if not isinstance(other, Set):
            raise ValueError("other must be a Set instance")
        for item in self.items:
            if item not in other.items:
                return False
        return True

    def issuperset(self, other: "Set[T]") -> bool:
        """Is this set a superset of *other*?

        Returns a ``bool``.
        """

        if not isinstance(other, Set):
            raise ValueError("other must be a Set instance")
        for item in other.items:
            if item not in self.items:
                return False
        return True

    def isdisjoint(self, other: "Set[T]") -> bool:
        if not isinstance(other, Set):
            raise ValueError("other must be a Set instance")
        for item in other.items:
            if item in self.items:
                return False
        return True
