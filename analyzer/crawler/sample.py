"""A reproducible subset of the index, for work that cannot afford all of it."""

from collections.abc import Sequence

from analyzer.crawler.registry import ServerRecord
from analyzer.errors import InputError
from analyzer.sampling import draw


def sample_index(
    records: Sequence[ServerRecord], size: int, *, seed: int
) -> list[ServerRecord]:
    """Draw `size` records at random, reproducibly, on any machine.

    The draw depends on the seed and the server ids and on nothing else. In
    particular it does not depend on the order the records arrive in, which
    comes from the registry's paging and is not guaranteed stable: a draw that
    depended on it would give two machines different samples from the same
    seed, and neither would have any way to notice. The method itself lives in
    `analyzer.sampling`, shared with the golden set so that the project has
    one published sampling method rather than two that could drift.

    The repository URL follows the server id as a tie-break, which makes the
    order total. A duplicate id should not occur, since `collapse_to_index`
    keys on the repository and registry names are unique, but "should not
    occur" is not a property the draw needs to rely on.

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

    return draw(records, size, seed=seed, key=lambda r: (r.server_id, r.repo_url))
