import json
from pathlib import Path

from analyzer.crawler.corpus import build_corpus
from analyzer.crawler.coverage import Coverage, render_coverage, write_corpus
from analyzer.crawler.registry import Crawl, ServerRecord


def _crawl() -> Crawl:
    records = tuple(
        ServerRecord(server_id=name, repo_url=url, discovered_via="registry")
        for name, url in [
            ("one/a", "https://github.com/shared/repo"),
            ("two/b", "https://github.com/shared/repo"),
            ("three/c", "https://github.com/shared/repo"),
            ("four/d", "https://github.com/solo/repo"),
        ]
    )
    return Crawl(records=records, entries_seen=10, skipped_without_source=6)


def _coverage() -> Coverage:
    crawl = _crawl()
    return Coverage(
        crawled_at="2026-09-21T00:00:00Z",
        entries_seen=crawl.entries_seen,
        skipped_without_source=crawl.skipped_without_source,
        corpus=build_corpus(crawl.records),
    )


def test_every_entry_is_accounted_for() -> None:
    """The intake rules are only credible if the arithmetic closes.

    Entries seen must equal those with no source, plus those collapsed into a
    repository already counted, plus the repositories scanned. A summary where
    servers merely disappear between two numbers is the thing this document
    exists to stop being possible.
    """
    coverage = _coverage()

    assert (
        coverage.skipped_without_source
        + coverage.corpus.entries_collapsed
        + coverage.corpus.repository_count
        == coverage.entries_seen
    )


def test_the_summary_states_each_rule_and_what_it_cost() -> None:
    """Each rule is named, given a number, and reconciled against the total.

    Asserted on the reconciliation sentence rather than on loose substrings.
    Checking that "2" appears somewhere in a document full of numbers proves
    nothing, and would keep passing if the arithmetic were rearranged wrongly.
    """
    rendered = render_coverage(_coverage())
    lowered = rendered.lower()

    assert "2026-09-21T00:00:00Z" in rendered
    assert "no source to read" in lowered
    assert "collapsed" in lowered
    assert "distinct repositories" in lowered
    assert "6 + 2 + 2 = 10, against 10 entries seen" in rendered


def test_the_summary_is_byte_identical_for_the_same_crawl() -> None:
    """A committed document must not churn when nothing changed.

    Two crawls that found the same thing produce the same file, so a diff in
    the repository always means the ecosystem moved.
    """
    assert render_coverage(_coverage()) == render_coverage(_coverage())


def test_writing_the_corpus_produces_a_file_that_reads_back(tmp_path: Path) -> None:
    coverage = _coverage()
    destination = tmp_path / "nested" / "corpus.json"

    write_corpus(destination, coverage)

    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["crawled_at"] == "2026-09-21T00:00:00Z"
    assert payload["entries_seen"] == 10
    assert len(payload["repositories"]) == 2


def test_the_corpus_records_the_names_that_claim_each_repository(tmp_path: Path) -> None:
    """The generated corpus keeps what the committed summary cannot.

    The summary is a few dozen lines a reviewer reads. The corpus is the
    evidence behind it, and a repository claimed by 2,332 names has to carry
    all of them or the claim is unverifiable.
    """
    destination = tmp_path / "corpus.json"

    write_corpus(destination, _coverage())

    payload = json.loads(destination.read_text(encoding="utf-8"))
    shared = next(r for r in payload["repositories"] if r["repo_url"].endswith("shared/repo"))
    assert shared["server_ids"] == ["one/a", "three/c", "two/b"]


def test_large_counts_are_readable() -> None:
    """This document is read by people, and the numbers are its whole point.

    A published figure of 34212 asks the reader to count digits before they can
    tell it from 3421 or 342120.
    """
    crawl = Crawl(
        records=tuple(
            ServerRecord(
                server_id=f"pub/name-{n}",
                repo_url=f"https://github.com/owner/repo-{n // 3}",
                discovered_via="registry",
            )
            for n in range(34212)
        ),
        entries_seen=48000,
        skipped_without_source=13788,
    )

    rendered = render_coverage(Coverage.from_crawl(crawl, crawled_at="2026-09-21T00:00:00Z"))

    assert "48,000" in rendered
    assert "13,788" in rendered
    assert "34212" not in rendered
