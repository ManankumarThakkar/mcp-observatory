"""One sampling method, so every draw this project publishes is the same one."""

import hashlib
from collections.abc import Callable, Sequence
from typing import TypeVar

T = TypeVar("T")


def draw(
    items: Sequence[T], size: int, *, seed: int, key: Callable[[T], tuple[str, ...]]
) -> list[T]:
    """Take `size` items at random, reproducibly, ordered by hashed identity.

    A hash rather than a seeded shuffle. Both are uniform; only this one is
    reproducible by somebody not running our code, because sha256 of
    "<seed>:<identity>" is the entire method and can be reimplemented in any
    language. `random.seed` fixes the stream, not the algorithm consuming it,
    so a future Python could quietly redefine what a published figure
    describes.

    It also has a property a shuffle does not, and this is the one that earns
    its place here: an item's position depends only on its own identity and
    the seed, so drawing again from a larger population leaves every item
    already drawn exactly where it was. That is what lets a golden set grow
    without invalidating labels somebody spent hours making.

    `key` returns the identity as a tuple. The first element is hashed; the
    whole tuple breaks ties, which makes the order total. Without a tie-break,
    two items sharing a hashed identity would be ordered by whichever arrived
    first, reintroducing exactly the dependence on input order this removes.
    """
    def order(item: T) -> tuple[str, ...]:
        parts = key(item)
        return (hashlib.sha256(f"{seed}:{parts[0]}".encode()).hexdigest(), *parts)

    return sorted(items, key=order)[:size]
