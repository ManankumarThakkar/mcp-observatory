"""A reproducible subset of the index, for work that cannot afford all of it."""

import hashlib
from collections.abc import Sequence

from analyzer.crawler.registry import ServerRecord
from analyzer.errors import InputError


def _draw_key(seed: int, record: ServerRecord) -> tuple[str, str, str]:
    """Where this record falls in the draw, for this seed.

    A hash rather than `random.sample`. Both are uniform, but only this one is
    reproducible by somebody who is not running our code: sha256 of
    "<seed>:<server_id>" is the whole method, so a reader can regenerate the
    sample in any language, and a future Python whose `random.sample`
    algorithm differs cannot quietly redefine which repositories the published
    figures describe. `random.seed` fixes the stream, not the algorithm that
    consumes it.

    The id and the URL follow as tie-breaks, which makes the order total. Two
    records sharing a server_id tie on the hash, and Python's sort is stable,
    so without a tie-break they would be ordered by whichever arrived first -
    reintroducing exactly the dependence on input order this exists to remove.
    A duplicate id should not occur, since `collapse_to_index` keys on the
    repository and registry names are unique, but "should not occur" is not a
    property the draw needs to rely on.
    """
    digest = hashlib.sha256(f"{seed}:{record.server_id}".encode()).hexdigest()
    return digest, record.server_id, record.repo_url


def sample_index(
    records: Sequence[ServerRecord], size: int, *, seed: int
) -> list[ServerRecord]:
    """Draw `size` records at random, reproducibly, on any machine.

    The draw depends on the seed and the server ids and on nothing else. In
    particular it does not depend on the order the records arrive in, which
    comes from the registry's paging and is not guaranteed stable: a draw that
    depended on it would give two machines different samples from the same
    seed, and neither would have any way to notice.

    A size at or above the corpus returns the whole corpus, because asking for
    more than exists describes a smaller corpus rather than a mistake. Zero, a
    negative size, and an empty corpus are all refused: each would scan
    nothing, and a run that scanned nothing is indistinguishable downstream
    from a healthy run over a dead ecosystem. That is the same failure
    `build_corpus` refuses for the same reason.
    """
    if size <= 0:
        raise InputError(f"size must be positive, got {size}")
    if not records:
        raise InputError(
            "cannot sample an empty index; an index with no servers is a broken "
            "crawl rather than an ecosystem with nothing in it"
        )

    ordered = sorted(records, key=lambda record: _draw_key(seed, record))
    return ordered[:size]
