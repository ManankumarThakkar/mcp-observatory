import pytest

from analyzer.crawler.registry import ServerRecord
from analyzer.crawler.sample import sample_index


def _records(count: int) -> list[ServerRecord]:
    return [
        ServerRecord(
            server_id=f"owner/repo-{n:04d}",
            repo_url=f"https://github.com/owner/repo-{n:04d}",
            discovered_via="registry",
        )
        for n in range(count)
    ]


def test_the_same_seed_draws_the_same_subset() -> None:
    """A published sampling method has to be re-runnable by a reader.

    "The 2,000-repository sample" has to name one specific set of
    repositories, or every figure drawn from it describes a set nobody else
    can assemble.
    """
    records = _records(100)

    assert sample_index(records, 10, seed=7) == sample_index(records, 10, seed=7)


def test_a_different_seed_draws_a_different_subset() -> None:
    """Otherwise the seed is decoration and the subset is fixed forever."""
    assert sample_index(_records(100), 10, seed=7) != sample_index(_records(100), 10, seed=8)


def test_input_order_does_not_change_the_subset() -> None:
    """The index's order comes from the registry's paging, which is not
    guaranteed stable. If the draw depended on it, the same seed would quietly
    disagree between two machines that crawled on different days.
    """
    records = _records(100)

    assert sample_index(records, 10, seed=7) == sample_index(list(reversed(records)), 10, seed=7)


def test_the_draw_is_not_the_first_n_in_any_order_the_input_arrived_in() -> None:
    """A subset that is alphabetical by server_id correlates with whatever
    else is alphabetical: publisher, namespace, and the account that
    registered two thousand names in one sitting.
    """
    drawn = {record.server_id for record in sample_index(_records(500), 20, seed=7)}
    alphabetical = {f"owner/repo-{n:04d}" for n in range(20)}

    assert drawn != alphabetical


def test_the_draw_spreads_across_the_corpus_rather_than_clustering() -> None:
    """A weak hash or a truncated key would put the whole sample in one
    region of the sorted order, which no single-value assertion would catch.
    """
    drawn = sorted(
        int(record.server_id.rsplit("-", 1)[1])
        for record in sample_index(_records(1000), 100, seed=7)
    )

    # Every tenth of the corpus should contribute roughly ten of the hundred.
    buckets = [sum(1 for n in drawn if bucket * 100 <= n < (bucket + 1) * 100) for bucket in range(10)]
    assert all(3 <= count <= 20 for count in buckets), buckets


def test_asking_for_more_than_exists_returns_everything() -> None:
    """A subset larger than the corpus is a smaller corpus, not an error."""
    assert len(sample_index(_records(5), 50, seed=7)) == 5


def test_asking_for_exactly_the_corpus_returns_all_of_it() -> None:
    """The boundary between "sample" and "everything", where an off-by-one
    would silently drop one repository from a full run.
    """
    assert len(sample_index(_records(50), 50, seed=7)) == 50


def test_a_non_positive_size_is_refused() -> None:
    """Zero would scan nothing, which is indistinguishable downstream from a
    crawl that found nothing.
    """
    with pytest.raises(ValueError, match="positive"):
        sample_index(_records(5), 0, seed=7)


def test_a_negative_size_is_refused() -> None:
    """A slice with a negative bound silently returns a different set rather
    than failing, so this cannot be left to the slice.
    """
    with pytest.raises(ValueError, match="positive"):
        sample_index(_records(5), -3, seed=7)


def test_sampling_an_empty_corpus_is_refused() -> None:
    """Returning [] would scan nothing and look exactly like a healthy run
    over a dead ecosystem, which is the failure build_corpus already refuses.
    """
    with pytest.raises(ValueError, match="empty"):
        sample_index([], 10, seed=7)


def test_duplicate_server_ids_do_not_make_the_draw_depend_on_input_order() -> None:
    """Two records sharing an id would otherwise tie on the sort key, and the
    tie would be broken by whichever arrived first.
    """
    duplicated = [
        ServerRecord(server_id="a/dup", repo_url="https://github.com/a/one", discovered_via="registry"),
        ServerRecord(server_id="a/dup", repo_url="https://github.com/a/two", discovered_via="registry"),
        *_records(10),
    ]

    assert sample_index(duplicated, 5, seed=7) == sample_index(list(reversed(duplicated)), 5, seed=7)


def test_the_published_method_is_pinned_to_an_exact_expected_draw() -> None:
    """The sampling method is published, so changing how it draws changes what
    every published figure describes. This is derived from the stated method -
    order by sha256("<seed>:<server_id>"), take the first n - computed
    independently of this implementation, so a rewrite that quietly changes
    the draw fails here rather than silently renaming the corpus.
    """
    drawn = [record.server_id for record in sample_index(_records(20), 3, seed=7)]

    assert drawn == ["owner/repo-0008", "owner/repo-0013", "owner/repo-0015"]
