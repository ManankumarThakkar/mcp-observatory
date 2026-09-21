import json
from pathlib import Path

from analyzer.crawler.corpus import build_corpus
from analyzer.crawler.coverage import Coverage, Sample, render_coverage, write_corpus
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


def _sample(*repo_urls: str) -> Sample:
    return Sample(
        repo_urls=tuple(repo_urls),
        queries=('"@modelcontextprotocol/sdk" filename:package.json',),
        requests_spent=200,
    )


def test_the_sample_reports_how_much_of_it_the_census_already_had() -> None:
    """The overlap is the finding, so it is computed rather than asserted.

    A sample that mostly duplicates the registry would mean code search adds
    little. A sample that barely overlaps means the registry covers a small
    share of what exists, which is what the measurement showed.
    """
    coverage = Coverage(
        crawled_at="2026-09-21T00:00:00Z",
        entries_seen=10,
        skipped_without_source=6,
        corpus=build_corpus(_crawl().records),
        sample=_sample(
            "https://github.com/shared/repo",
            "https://github.com/brand/new",
            "https://github.com/another/new",
        ),
    )

    assert coverage.sample_size == 3
    assert coverage.sample_already_in_census == 1
    assert coverage.sample_beyond_census == 2


def test_the_census_comparison_ignores_url_casing() -> None:
    """Registry URLs carry whatever case the publisher typed.

    A live registry entry reads `https://github.com/DIGIBIZ360-COM/adoraads`,
    while code search reports the repository's canonical name. Comparing them
    literally would count the same repository as a new discovery and overstate
    what the registry is missing, which is precisely the claim being made.
    """
    crawl = Crawl(
        records=(
            ServerRecord(
                server_id="one/a",
                repo_url="https://github.com/Mixed-Case/Repo",
                discovered_via="registry",
            ),
        ),
        entries_seen=1,
        skipped_without_source=0,
    )
    coverage = Coverage(
        crawled_at="2026-09-21T00:00:00Z",
        entries_seen=1,
        skipped_without_source=0,
        corpus=build_corpus(crawl.records),
        sample=_sample("https://github.com/mixed-case/repo"),
    )

    assert coverage.sample_beyond_census == 0


def test_the_sample_never_changes_the_census_arithmetic() -> None:
    """The whole reason these are two populations and not one list.

    The census is reproducible: the same crawl gives the same number. The
    sample depends on how long the pass ran. Letting the second move the first
    would destroy the property that makes the census worth publishing.
    """
    without = Coverage(
        crawled_at="2026-09-21T00:00:00Z",
        entries_seen=10,
        skipped_without_source=6,
        corpus=build_corpus(_crawl().records),
    )
    with_sample = Coverage(
        crawled_at="2026-09-21T00:00:00Z",
        entries_seen=10,
        skipped_without_source=6,
        corpus=build_corpus(_crawl().records),
        sample=_sample("https://github.com/brand/new"),
    )

    assert with_sample.corpus == without.corpus
    assert with_sample.entries_seen == without.entries_seen
    assert "6 + 2 + 2 = 10, against 10 entries seen" in render_coverage(with_sample)


def test_the_summary_marks_the_sample_as_a_sample() -> None:
    rendered = render_coverage(
        Coverage(
            crawled_at="2026-09-21T00:00:00Z",
            entries_seen=10,
            skipped_without_source=6,
            corpus=build_corpus(_crawl().records),
            sample=_sample("https://github.com/brand/new"),
        )
    )

    assert "not a census" in rendered.lower()
    assert "candidate" in rendered.lower()


def test_a_crawl_without_a_sample_has_no_sample_section() -> None:
    rendered = render_coverage(_coverage())

    assert "sample" not in rendered.lower()


def test_the_corpus_keeps_the_sample_separate_from_the_census(tmp_path: Path) -> None:
    coverage = Coverage(
        crawled_at="2026-09-21T00:00:00Z",
        entries_seen=10,
        skipped_without_source=6,
        corpus=build_corpus(_crawl().records),
        sample=_sample("https://github.com/brand/new"),
    )
    destination = tmp_path / "corpus.json"

    write_corpus(destination, coverage)

    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["beyond_the_registry"]["repo_urls"] == ["https://github.com/brand/new"]
    assert len(payload["repositories"]) == 2
