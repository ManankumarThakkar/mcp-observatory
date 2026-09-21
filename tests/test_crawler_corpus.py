import pytest

from analyzer.crawler.corpus import Corpus, Repository, build_corpus
from analyzer.crawler.registry import ServerRecord


def _record(server_id: str, repo_url: str) -> ServerRecord:
    return ServerRecord(server_id=server_id, repo_url=repo_url, discovered_via="registry")


def test_one_entry_becomes_one_repository() -> None:
    corpus = build_corpus([_record("ac.tandem/docs-mcp", "https://github.com/a/b")])

    assert corpus.repositories == (
        Repository(repo_url="https://github.com/a/b", server_ids=("ac.tandem/docs-mcp",)),
    )


def test_entries_sharing_a_repository_collapse_into_one() -> None:
    """The measured shape of the live registry, in miniature.

    One account holds 2,332 registered names pointing at a single repository.
    Scanning per entry would clone it 2,332 times and publish its findings as
    2,332 distinct vulnerable servers, making one account 9% of the index.
    """
    corpus = build_corpus(
        [
            _record("io.github.squatter/aba-ok", "https://github.com/squatter/one"),
            _record("io.github.squatter/abnf-ok", "https://github.com/squatter/one"),
            _record("io.github.honest/real", "https://github.com/honest/real"),
        ]
    )

    assert len(corpus.repositories) == 2
    squatted = next(r for r in corpus.repositories if r.repo_url.endswith("/one"))
    assert squatted.server_ids == (
        "io.github.squatter/aba-ok",
        "io.github.squatter/abnf-ok",
    )


def test_the_names_claiming_a_repository_are_kept_not_discarded() -> None:
    """Collapsing must not lose who claimed what.

    The index still has to be able to say that a repository is published under
    many names, which is itself a signal. Dropping the names would turn a
    reportable fact into a silent deletion.
    """
    corpus = build_corpus(
        [
            _record("b/second", "https://github.com/a/b"),
            _record("a/first", "https://github.com/a/b"),
        ]
    )

    assert corpus.repositories[0].claim_count == 2
    assert set(corpus.repositories[0].server_ids) == {"a/first", "b/second"}


def test_the_corpus_is_ordered_deterministically() -> None:
    """Two crawls of the same registry must produce the same file.

    The registry's page order is not guaranteed stable, and an unordered corpus
    would produce a different committed summary on every run for no reason.
    """
    records = [
        _record("z/last", "https://github.com/z/z"),
        _record("a/first", "https://github.com/a/a"),
        _record("m/middle", "https://github.com/m/m"),
    ]

    forwards = build_corpus(records)
    backwards = build_corpus(list(reversed(records)))

    assert forwards == backwards
    assert [r.repo_url for r in forwards.repositories] == [
        "https://github.com/a/a",
        "https://github.com/m/m",
        "https://github.com/z/z",
    ]


def test_the_corpus_counts_what_the_intake_rules_cost() -> None:
    """The counts are the published claim, so they are computed, not narrated."""
    corpus = build_corpus(
        [
            _record("one/a", "https://github.com/shared/repo"),
            _record("two/b", "https://github.com/shared/repo"),
            _record("three/c", "https://github.com/shared/repo"),
            _record("four/d", "https://github.com/solo/repo"),
        ]
    )

    assert corpus.entries_seen == 4
    assert corpus.repository_count == 2
    assert corpus.entries_collapsed == 2
    assert corpus.most_claimed_count == 3


def test_an_empty_crawl_is_refused() -> None:
    """A crawl that found nothing is a broken upstream, not an empty ecosystem.

    Publishing zero looks identical to a healthy crawl of a dead ecosystem, and
    the difference is the whole value of the index.
    """
    with pytest.raises(ValueError, match="no repositories"):
        build_corpus([])


def test_a_corpus_round_trips_through_its_serialised_form() -> None:
    corpus = build_corpus(
        [
            _record("one/a", "https://github.com/shared/repo"),
            _record("two/b", "https://github.com/shared/repo"),
        ]
    )

    assert Corpus.from_dict(corpus.to_dict()) == corpus
