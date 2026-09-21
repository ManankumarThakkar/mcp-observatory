"""A JSON fetch that survives the failures the registry actually produces."""

import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

JsonObject = dict[str, Any]

# Measured against the live registry on 2026-09-21. The response carries
# exactly: connection, content-length, content-type, date,
# strict-transport-security, vary, x-registry-cache. There is no
# X-RateLimit-Remaining and no X-RateLimit-Reset, so nothing here reads them.
# Those are one code host's convention, and honouring a header the server never
# sends is a branch no real response can reach.
#
# Retry-After is honoured instead. It is ordinary HTTP rather than any single
# vendor's invention, so it costs three lines and works against whatever the
# registry becomes.
RETRYABLE_STATUSES = frozenset({429, 500, 502, 503, 504})

# A ceiling on any single wait, whatever the server asks for. The registry is
# not hostile, but a wait is a value taken from a remote response, and one
# absurd number should not be able to park a nightly run for a day.
MAX_BACKOFF_SECONDS = 60.0

REQUEST_TIMEOUT_SECONDS = 30.0


class FetchFailed(Exception):
    """Raised when a URL could not be fetched as JSON.

    Fatal by design, like RegistryError. A crawl that silently drops a page it
    could not fetch publishes a smaller ecosystem and looks identical to a
    healthy crawl of a smaller ecosystem.
    """


@dataclass(frozen=True)
class Response:
    """One HTTP response, reduced to the three things this module reads.

    `headers` keys are lowercase. HTTP header names are case-insensitive, and
    normalising once at the boundary means every lookup below can be a plain
    dict access rather than each caller remembering to be careful.
    """

    status: int
    headers: Mapping[str, str]
    body: bytes


Opener = Callable[[str], Response]


def as_response(error: urllib.error.HTTPError) -> Response:
    """Turn urllib's exception for a non-2xx status back into a response.

    urlopen raises on 4xx and 5xx rather than returning them, and HTTPError
    subclasses OSError. Left alone, every 404 would be indistinguishable from a
    dropped connection and retried five times, and a 429's Retry-After would
    never be read at all. The exception already carries the status, headers and
    body, so this is a conversion rather than a recovery.
    """
    return Response(
        status=error.code,
        headers={key.lower(): value for key, value in error.headers.items()},
        body=error.read(),
    )


def _urlopen(url: str) -> Response:
    """Fetch over https only, with a timeout.

    The scheme check is defence in depth rather than input validation: this
    module's only caller builds its URLs from a constant. It costs one line and
    means a future caller cannot turn this into a reader of local files.
    """
    if urlparse(url).scheme != "https":
        raise FetchFailed(f"refusing to fetch a non-https url: {url}")

    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            return Response(
                status=response.status,
                headers={key.lower(): value for key, value in response.headers.items()},
                body=response.read(),
            )
    except urllib.error.HTTPError as error:
        return as_response(error)


def _retry_after(headers: Mapping[str, str]) -> float | None:
    """The server's own requested wait, in seconds, if it gave one.

    Only the delta-seconds form is read. Retry-After may also be an HTTP date,
    which needs a clock to interpret and therefore a clock to inject; no
    observed response uses that form, so reading it would be a parameter no
    test could justify. An unparsable value falls back to the backoff schedule,
    which is the safe direction.
    """
    raw = headers.get("retry-after")
    if raw is None:
        return None
    try:
        return min(float(raw), MAX_BACKOFF_SECONDS)
    except ValueError:
        return None


def _decode(url: str, body: bytes) -> JsonObject:
    """Decode a successful body, or say plainly that it was not JSON.

    A JSON document is not necessarily an object, and everything downstream
    reads this by key. A bare list or string would otherwise fail later with an
    error about the wrong thing.
    """
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FetchFailed(f"{url} returned a body that is not JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise FetchFailed(f"{url} returned JSON that is not an object: {type(payload).__name__}")
    return payload


def http_fetch(
    url: str,
    *,
    opener: Opener = _urlopen,
    sleep: Callable[[float], None] = time.sleep,
    max_attempts: int = 5,
) -> JsonObject:
    """GET a JSON document, retrying the failures that are worth retrying.

    Retried: a dropped connection or timeout, and the statuses a server uses to
    say "not now". Both are transient by definition, and a crawl of several
    hundred pages will meet them.

    Not retried: any other 4xx, and a body that is not JSON. Asking again for a
    URL that does not exist gets the same answer more slowly, and turning a
    permanent failure into five of them hides the real error behind a delay.

    `sleep` is injected so the retry schedule is assertable without a test that
    actually waits seven seconds. A test that slow gets deleted within a week,
    and then nothing checks the backoff at all.
    """
    last_error = ""

    for attempt in range(max_attempts):
        try:
            response = opener(url)
        except OSError as exc:
            # Covers the whole transport family, including URLError and socket
            # timeouts, both of which subclass OSError. HTTPError does too, but
            # never reaches here: _urlopen converts it to a Response so its
            # status and headers are read rather than discarded.
            last_error = f"{type(exc).__name__}: {exc}"
            delay = 2.0**attempt
        else:
            if response.status == 200:
                return _decode(url, response.body)

            if response.status not in RETRYABLE_STATUSES:
                raise FetchFailed(f"{url} returned HTTP {response.status}")

            last_error = f"HTTP {response.status}"
            delay = _retry_after(response.headers) or 2.0**attempt

        # No sleep after the final attempt: nothing follows it, and a nightly
        # run should fail at once rather than a minute later.
        if attempt < max_attempts - 1:
            sleep(min(delay, MAX_BACKOFF_SECONDS))

    raise FetchFailed(f"{url} still failing after {max_attempts} attempts ({last_error})")
