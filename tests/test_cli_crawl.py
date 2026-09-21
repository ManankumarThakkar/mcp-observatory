import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from analyzer.cli import EXIT_SCAN_FAILED, main, run_crawl
from analyzer.crawler.http import FetchFailed, JsonObject

FIXED_NOW = datetime(2026, 9, 21, 4, 5, 6, tzinfo=UTC)

PAGE = {
    "servers": [
        {"server": {"name": "one/a", "repository": {"url": "https://github.com/shared/repo"}}},
        {"server": {"name": "two/b", "repository": {"url": "https://github.com/shared/repo"}}},
        {"server": {"name": "three/c", "repository": {"url": "https://github.com/solo/repo"}}},
        {"server": {"name": "four/d", "remotes": [{"url": "https://hosted.test"}]}},
    ],
    "metadata": {"nextCursor": None},
}


def test_a_crawl_writes_a_summary_and_a_corpus(tmp_path: Path) -> None:
    summary = tmp_path / "coverage.md"
    corpus = tmp_path / "corpus.json"

    coverage = run_crawl(
        fetch=lambda url: PAGE,
        now=lambda: FIXED_NOW,
        summary_path=summary,
        corpus_path=corpus,
    )

    assert coverage.entries_seen == 4
    assert coverage.corpus.repository_count == 2
    assert "2026-09-21T04:05:06Z" in summary.read_text(encoding="utf-8")
    assert json.loads(corpus.read_text(encoding="utf-8"))["entries_seen"] == 4


def test_the_timestamp_is_utc_and_has_no_microseconds(tmp_path: Path) -> None:
    """A committed document must not churn on sub-second noise.

    A naive local timestamp would also make two runs on different machines
    disagree about when the same registry was read.
    """
    coverage = run_crawl(
        fetch=lambda url: PAGE,
        now=lambda: datetime(2026, 9, 21, 4, 5, 6, 123456, tzinfo=UTC),
        summary_path=tmp_path / "coverage.md",
        corpus_path=tmp_path / "corpus.json",
    )

    assert coverage.crawled_at == "2026-09-21T04:05:06Z"


def test_a_failed_crawl_writes_nothing(tmp_path: Path) -> None:
    """A partial crawl must not overwrite a good summary.

    The committed document is a published claim. Replacing it with the results
    of a run that died halfway would understate the ecosystem and look exactly
    like the ecosystem having shrunk.
    """
    summary = tmp_path / "coverage.md"
    summary.write_text("# Coverage\n\nprevious good run\n", encoding="utf-8")

    def fetch(url: str) -> JsonObject:
        raise FetchFailed("registry unreachable")

    with pytest.raises(FetchFailed):
        run_crawl(
            fetch=fetch,
            now=lambda: FIXED_NOW,
            summary_path=summary,
            corpus_path=tmp_path / "corpus.json",
        )

    assert summary.read_text(encoding="utf-8") == "# Coverage\n\nprevious good run\n"
    assert not (tmp_path / "corpus.json").exists()


def test_the_scan_subcommand_still_scans(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text("print('hello')\n", encoding="utf-8")

    assert main(["scan", "--path", str(tmp_path), "--server-id", "owner/repo"]) == 0


def test_a_crawl_that_cannot_reach_the_registry_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(url: str) -> JsonObject:
        raise FetchFailed("registry unreachable")

    monkeypatch.setattr("analyzer.cli.http_fetch", explode)
    monkeypatch.chdir(tmp_path)

    assert main(["crawl"]) == EXIT_SCAN_FAILED


def test_a_crawl_can_include_the_code_search_sample(tmp_path: Path) -> None:
    def search(query: str, page: int) -> JsonObject:
        return {"items": [{"repository": {"full_name": "brand/new"}}]}

    coverage = run_crawl(
        fetch=lambda url: PAGE,
        now=lambda: FIXED_NOW,
        summary_path=tmp_path / "coverage.md",
        corpus_path=tmp_path / "corpus.json",
        search=search,
        search_requests=3,
    )

    assert coverage.sample is not None
    assert coverage.sample_beyond_census == 1
    assert "not a census" in (tmp_path / "coverage.md").read_text(encoding="utf-8").lower()


def test_a_crawl_without_a_search_client_publishes_only_the_census(tmp_path: Path) -> None:
    """The registry crawl must not need a code host token to run.

    Code search requires authentication, and a contributor without a token
    should still be able to reproduce the census, which is the part the
    published figure rests on.
    """
    coverage = run_crawl(
        fetch=lambda url: PAGE,
        now=lambda: FIXED_NOW,
        summary_path=tmp_path / "coverage.md",
        corpus_path=tmp_path / "corpus.json",
    )

    assert coverage.sample is None


def test_code_search_without_a_token_fails_before_the_registry_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refusing late would waste the crawl and then publish the wrong thing.

    The caller asked for a census plus a sample. Discovering the missing token
    after ninety seconds of crawling would leave them with a census they did
    not ask for and an exit code they might not read.
    """
    read: list[str] = []

    def record(url: str) -> JsonObject:
        read.append(url)
        return PAGE

    monkeypatch.setattr("analyzer.cli.http_fetch", record)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)

    assert main(["crawl", "--with-code-search"]) == EXIT_SCAN_FAILED
    assert read == []
