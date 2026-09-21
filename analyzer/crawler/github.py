"""Find MCP servers that were published to a code host but never registered."""

import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from urllib.parse import urlencode

from analyzer.crawler.http import (
    REQUEST_TIMEOUT_SECONDS,
    JsonObject,
    Opener,
    Response,
    as_response,
    http_fetch,
)
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
# The count is chosen to spend the budget, which an earlier four-bucket list
# did not. Each bucket serves at most 1,000 results, so a query crossed with
# four buckets tops out at 40 requests and two queries at 80. A live run spent
# exactly that and stopped, leaving 60% of the allowance unused, because the
# plan ran out rather than the budget. Ten buckets across two queries is 200
# requests, which is the budget exactly.
#
# They stay uneven on purpose. The ranges are narrow where files cluster:
# 71,168 of the npm query's matches fall between 500 and 2,000 bytes against
# 14,816 below 500, so an evenly spaced list would waste requests on empty
# ranges and cap out inside the crowded one.
#
# Enumerating everything would need 150 to 300 buckets, which is 2.5 to 5
# hours at ten requests a minute, against a six-hour job limit that still has
# to scan what it finds. A bounded pass that rotates is worth more than an
# exhaustive one that never finishes.
SIZE_BUCKETS: tuple[str, ...] = (
    "size:0..200",
    "size:200..500",
    "size:500..800",
    "size:800..1100",
    "size:1100..1400",
    "size:1400..1700",
    "size:1700..2000",
    "size:2000..3500",
    "size:3500..10000",
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


SEARCH_ENDPOINT = "https://api.github.com/search/code"

# Ten requests a minute, so one every six seconds with a little room. Waiting
# before each request rather than after the failure is deliberate: exceeding
# the limit returns a 403 whose body has no items, which this module treats as
# fatal, so a pass that paced itself badly would stop rather than degrade.
PACE_SECONDS = 6.5


def _authorised_opener(token: str) -> Opener:
    """An opener that authenticates, reusing the retry logic in `http_fetch`.

    Code search rejects anonymous requests outright, so the token is not an
    optimisation. Building an opener rather than threading a token through
    `http_fetch` keeps that module free of any one host's authentication.
    """

    def opener(url: str) -> Response:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                return Response(
                    status=response.status,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=response.read(),
                )
        except urllib.error.HTTPError as error:
            return as_response(error)

    return opener


def github_search(token: str, *, sleep: Callable[[float], None] = time.sleep) -> SearchFn:
    """Build a search callable that keeps itself under the rate limit."""
    opener = _authorised_opener(token)

    def search(query: str, page: int) -> JsonObject:
        sleep(PACE_SECONDS)
        url = f"{SEARCH_ENDPOINT}?" + urlencode(
            {
                "q": query,
                "per_page": RESULTS_PER_PAGE,
                "page": page,
                "sort": "indexed",
                "order": "desc",
            }
        )
        return http_fetch(url, opener=opener)

    return search
