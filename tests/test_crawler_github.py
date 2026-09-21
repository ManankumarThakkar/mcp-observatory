from collections.abc import Callable

import pytest

from analyzer.crawler.github import (
    DEFAULT_MAX_REQUESTS,
    MAX_PAGES,
    RESULTS_PER_PAGE,
    SEARCH_QUERIES,
    SIZE_BUCKETS,
    GitHubSearchError,
    iter_discoveries,
)
from analyzer.crawler.http import JsonObject


def _page(*full_names: str) -> JsonObject:
    return {"items": [{"repository": {"full_name": name}} for name in full_names]}


def _script(pages: list[JsonObject]) -> Callable[[str, int], JsonObject]:
    """A search that serves a fixed list of pages, recording nothing.

    Injected like `fetch` in the registry client: the thing under test is how
    many requests are spent and when paging stops, neither of which is
    observable against a live endpoint under a 10-per-minute budget.
    """
    remaining = list(pages)

    def search(query: str, page: int) -> JsonObject:
        return remaining.pop(0) if remaining else _page()

    return search


def test_a_search_hit_becomes_a_record() -> None:
    records = list(iter_discoveries(_script([_page("owner/repo")]), max_requests=1))

    assert len(records) == 1
    assert records[0].repo_url == "https://github.com/owner/repo"
    assert records[0].server_id == "owner/repo"
    assert records[0].discovered_via == "code-search"


def test_the_same_repository_found_twice_is_yielded_once() -> None:
    """Two queries match the same repository constantly.

    A repository with both a package manifest and a Python entry point matches
    the npm query and the Python query, and every size bucket of a query can
    return a file from a repository another bucket already returned.
    """
    pages = [_page("a/one", "a/one", "b/two"), _page("b/two", "c/three")]

    records = list(iter_discoveries(_script(pages), max_requests=2))

    assert [r.server_id for r in records] == ["a/one", "b/two", "c/three"]


def test_the_request_budget_is_never_exceeded() -> None:
    """Code search allows ten requests a minute, so the budget is the design.

    Overrunning it does not fail loudly; it returns 403s that look like empty
    results, which would silently shrink the sample instead of stopping it.
    """
    spent = []

    def search(query: str, page: int) -> JsonObject:
        spent.append((query, page))
        return _page(f"owner/repo-{len(spent)}")

    list(iter_discoveries(search, max_requests=7))

    assert len(spent) == 7


def test_paging_stops_at_the_thousand_result_cap() -> None:
    """The API serves at most 1,000 results per query however many match.

    Asking for page 11 spends a request from a 10-per-minute budget and
    returns nothing, so the cap is respected rather than discovered.
    """
    full = [_page(*[f"owner/repo-{p}-{i}" for i in range(RESULTS_PER_PAGE)]) for p in range(20)]
    pages_requested = []

    def search(query: str, page: int) -> JsonObject:
        pages_requested.append(page)
        return full[len(pages_requested) - 1]

    list(iter_discoveries(search, max_requests=500, queries=("one query",), buckets=("",)))

    assert max(pages_requested) == MAX_PAGES


def test_a_short_page_ends_that_query_early() -> None:
    """A page below the page size is the last one, so asking again wastes budget."""
    pages_requested = []

    def search(query: str, page: int) -> JsonObject:
        pages_requested.append((query, page))
        return _page("owner/only")

    list(iter_discoveries(search, max_requests=10, queries=("q1", "q2"), buckets=("",)))

    assert pages_requested == [("q1", 1), ("q2", 1)]


def test_buckets_rotate_so_successive_runs_cover_different_slices() -> None:
    """A bounded pass cannot cover everything, so runs must not all cover the same part.

    Without rotation a nightly pass re-reads the same first bucket forever and
    the corpus stops growing after the first run.
    """
    seen: list[str] = []

    def search(query: str, page: int) -> JsonObject:
        seen.append(query)
        return _page()

    list(iter_discoveries(search, max_requests=1, queries=("q",), buckets=("A", "B", "C")))
    first = seen[0]
    seen.clear()

    list(iter_discoveries(search, max_requests=1, queries=("q",), buckets=("A", "B", "C"), offset=1))

    assert seen[0] != first


def test_a_response_without_items_is_fatal() -> None:
    """A shape change affects every result, not one, so it stops the run.

    Treating it as an empty page would publish a sample that silently lost a
    whole query, which reads exactly like that slice of the ecosystem being
    empty.
    """
    with pytest.raises(GitHubSearchError, match="items"):
        list(iter_discoveries(lambda q, p: {"message": "rate limited"}, max_requests=1))


def test_the_default_plan_can_actually_spend_the_default_budget() -> None:
    """A budget the plan cannot reach is not a budget, it is a decoration.

    Each query-and-bucket pair serves at most MAX_PAGES requests, so the plan
    has a hard ceiling whatever the budget says. A live run with four buckets
    spent 80 of its 200 allowed requests and stopped, because the plan ran out
    rather than the allowance, and the sample was a third of what the same
    twenty minutes could have produced. Nothing in the code said so.
    """
    reachable = len(SEARCH_QUERIES) * len(SIZE_BUCKETS) * MAX_PAGES

    assert reachable >= DEFAULT_MAX_REQUESTS, (
        f"the plan tops out at {reachable} requests but the budget allows "
        f"{DEFAULT_MAX_REQUESTS}; add buckets or lower the budget"
    )
