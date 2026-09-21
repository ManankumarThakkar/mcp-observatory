"""Discover MCP servers from the official registry."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

# Decoded JSON from a service we do not control. Deliberately not a TypedDict:
# the registry's shape is theirs to change, and a precise type here would be a
# claim about their API that we cannot enforce. Every field access below is
# therefore explicit about what it assumes.
JsonObject = dict[str, Any]

REGISTRY_ENDPOINT = "https://registry.modelcontextprotocol.io/v0/servers"

# The only transport a registry entry may name. Anyone can publish to the
# registry, so a repository URL is hostile input, and this is the boundary it
# enters through.
#
# The fetcher's own allowlist is wider: it permits `file:` so its tests can
# clone local repositories. A `file:///` entry here would therefore have it
# pull a repository off the runner's own disk and publish those paths under
# whatever server_id the attacker chose. Narrowing at the point of entry is
# better than widening the fetcher's tests, because the fetcher cannot know
# whether its caller trusted the URL.
ALLOWED_REPOSITORY_SCHEME = "https"

# The registry holds every published version of every server. Measured over 600
# live entries: 190 distinct servers, so most of a naive crawl is older
# versions of servers already seen. Asking the API for latest only is cheaper
# than paging through duplicates and discarding them here, and removes the
# deduplication logic entirely.
PAGE_SIZE = 100


class RegistryError(Exception):
    """Raised when the registry's response is not shaped the way it was.

    Deliberately fatal rather than skipped. A crawler that quietly yields
    nothing looks identical to a healthy crawl of an empty ecosystem, and the
    pipeline would publish that. Structure is the registry's contract; a break
    in it almost certainly affects every entry rather than one, so the run
    stops and says so.

    Content is different and is not an error: a server with no repository, or
    one whose repository is not reachable over https, is a fact about that
    server and is skipped.
    """


@dataclass(frozen=True)
class ServerRecord:
    """One server the registry knows about, as far as the registry can say.

    A deliberate subset of the index described in spec section 6.1. Language,
    star count and archived status are not in the registry's response at all;
    they come from the code host and arrive with that enrichment. Carrying them
    here as "unknown", 0 and False would be inventing values the schema
    promises and nothing supplies, which is the same reason Finding omits the
    fields its later layers fill.

    There is no commit_sha either. The fetcher reports the commit it actually
    received rather than being told one, so nothing upstream needs to guess.
    """

    server_id: str
    repo_url: str
    discovered_via: str


def _page_url(cursor: str | None) -> str:
    """Build the URL for one page.

    Cursors are opaque strings that contain characters with meaning in a query
    string: a live example is `ac.snag/snag:1.0.0`. They are percent-encoded
    rather than pasted in.
    """
    url = f"{REGISTRY_ENDPOINT}?limit={PAGE_SIZE}&version=latest"
    if cursor:
        url += f"&cursor={quote(cursor, safe='')}"
    return url


def iter_servers(
    fetch: Callable[[str], JsonObject], *, max_pages: int = 200
) -> Iterator[ServerRecord]:
    """Yield one record per registry entry.

    `fetch` takes a URL and returns decoded JSON. Every piece of registry
    knowledge stays in this module, so `fetch` is only ever "GET this, give me
    JSON", which is what keeps the network out of the tests and matches the
    signature the real HTTP client will have.
    """
    cursor: str | None = None

    # Bounded rather than "until the cursor runs out". A registry bug that
    # returns the same cursor forever would otherwise loop until the nightly
    # job is killed, with nothing in the output to say why.
    for _ in range(max_pages):
        payload = fetch(_page_url(cursor))
        yield from _records_in(payload)

        cursor = payload.get("metadata", {}).get("nextCursor")
        if not cursor:
            return


def _records_in(payload: JsonObject) -> Iterator[ServerRecord]:
    entries = payload.get("servers")
    if not isinstance(entries, list):
        raise RegistryError(f"registry payload has no 'servers' list: {sorted(payload)}")

    for entry in entries:
        server = entry.get("server") if isinstance(entry, dict) else None
        if not isinstance(server, dict):
            raise RegistryError(f"registry entry has no 'server' object: {str(entry)[:120]}")

        name = server.get("name")
        if not name:
            raise RegistryError(f"registry entry has no name: {str(server)[:120]}")

        # Roughly a third of the registry is hosted servers reached over HTTP,
        # which carry `remotes` and no repository. There is no source for a
        # static analyser to read, so they are skipped. Measured at 199 of 600
        # sampled entries, so this is the ordinary case rather than an error.
        repository = server.get("repository")
        if not repository:
            continue

        # Missing key versus empty value is the line between structure and
        # content. No "url" key at all means the response is not shaped the way
        # it was, which affects every entry. A key holding an empty string is
        # one bad record, and it falls through to the scheme check below like
        # any other URL that is not https.
        if not isinstance(repository, dict) or "url" not in repository:
            raise RegistryError(f"{name} has a repository with no url: {str(repository)[:120]}")

        repo_url = repository["url"]

        if urlparse(repo_url).scheme != ALLOWED_REPOSITORY_SCHEME:
            continue

        yield ServerRecord(
            server_id=name,
            repo_url=repo_url,
            discovered_via="registry",
        )
