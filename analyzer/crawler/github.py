"""Find MCP servers that were published to a code host but never registered."""

from collections.abc import Callable, Iterator

from analyzer.crawler.http import JsonObject
from analyzer.crawler.registry import ServerRecord

# Measured on 2026-09-21. Both queries match implementations and consumers
# alike: a repository that imports the server SDK may be a server, a client, a
# tutorial or a fork. Nothing here can tell those apart, which is why what this
# module produces is candidates rather than servers, and why the published
# sample says so.
SEARCH_QUERIES: tuple[str, ...] = (
    '"@modelcontextprotocol/sdk" filename:package.json',
    '"from mcp.server" language:python',
)

# The API serves at most 1,000 results for a query however many match, and
# 103,680 files match the first query alone. Splitting by file size is what
# reaches past the cap: the three ranges below divide that query into roughly
# 14,800, 71,200 and 20,500 files, measured rather than guessed.
#
# These are deliberately coarse. Fine enough buckets to enumerate everything
# would need 150 to 300 of them, which is 2.5 to 5 hours at ten requests a
# minute, against a six-hour job limit that still has to scan what it finds.
# A bounded pass that rotates is worth more than an exhaustive one that never
# finishes.
SIZE_BUCKETS: tuple[str, ...] = (
    "size:0..500",
    "size:500..2000",
    "size:2000..10000",
    "size:10000..100000",
)

RESULTS_PER_PAGE = 100

# 1,000 results at 100 a page. Asking for page 11 spends a request from a
# ten-per-minute budget and returns nothing.
MAX_PAGES = 10

# About twenty minutes at ten requests a minute. The scan is the expensive
# part of a nightly run, so discovery gets a small slice of the job.
DEFAULT_MAX_REQUESTS = 200

SearchFn = Callable[[str, int], JsonObject]


class GitHubSearchError(Exception):
    """Raised when a search response is not shaped the way it was.

    Fatal for the same reason RegistryError is. An unexpected shape affects
    every result rather than one, and treating it as an empty page would
    publish a sample that silently lost a whole query, which reads exactly
    like that slice of the ecosystem being empty.
    """


def _plan(queries: tuple[str, ...], buckets: tuple[str, ...], offset: int) -> list[str]:
    """Every query crossed with every size bucket, rotated by `offset`.

    Rotation is what makes a bounded pass worth running more than once.
    Without it a nightly run re-reads the same first bucket forever and the
    sample stops growing after the first night.
    """
    combined = [f"{query} {bucket}".strip() for query in queries for bucket in buckets]
    if not combined:
        return []
    start = offset % len(combined)
    return combined[start:] + combined[:start]


def _full_names(payload: JsonObject) -> Iterator[str]:
    items = payload.get("items")
    if not isinstance(items, list):
        raise GitHubSearchError(f"search response has no 'items' list: {sorted(payload)}")

    for item in items:
        repository = item.get("repository") if isinstance(item, dict) else None
        full_name = repository.get("full_name") if isinstance(repository, dict) else None
        if isinstance(full_name, str) and full_name:
            yield full_name


def iter_discoveries(
    search: SearchFn,
    *,
    queries: tuple[str, ...] = SEARCH_QUERIES,
    buckets: tuple[str, ...] = SIZE_BUCKETS,
    max_requests: int = DEFAULT_MAX_REQUESTS,
    offset: int = 0,
) -> Iterator[ServerRecord]:
    """Yield one record per distinct repository found, within a request budget.

    The budget is the design rather than a safety net. Overrunning ten
    requests a minute does not fail loudly: it returns 403s whose bodies
    deserialise to something without `items`, so an unbudgeted crawler would
    either crash mid-sample or, worse, shrink the sample silently.

    `server_id` is the repository's own name, because a repository found this
    way has no registered name. That is the honest identifier, and it also
    makes a repository found by both sources recognisable as one thing.
    """
    seen: set[str] = set()
    spent = 0

    for query in _plan(queries, buckets, offset):
        for page in range(1, MAX_PAGES + 1):
            if spent >= max_requests:
                return

            payload = search(query, page)
            spent += 1

            count = 0
            for full_name in _full_names(payload):
                count += 1
                if full_name in seen:
                    continue
                seen.add(full_name)
                yield ServerRecord(
                    server_id=full_name,
                    repo_url=f"https://github.com/{full_name}",
                    discovered_via="code-search",
                )

            # A page below the page size is the last one for this query, so
            # asking again buys nothing and costs a request from the budget.
            if count < RESULTS_PER_PAGE:
                break
