import email
import io
import json
import urllib.error
from collections.abc import Callable, Mapping

import pytest

from analyzer.crawler.http import FetchFailed, Response, _as_response, http_fetch

# Recorded from the live registry on 2026-09-21. The response carries no
# rate-limit headers of any kind, which is why nothing here honours them.
REGISTRY_HEADERS: Mapping[str, str] = {
    "content-type": "application/json",
    "vary": "Origin",
    "x-registry-cache": "HIT",
}


def _responses(*queued: Response | Exception) -> Callable[[str], Response]:
    """An opener that plays a fixed script, one entry per attempt.

    Injected rather than mocked: the caller is the registry crawler, and the
    thing under test is what `http_fetch` does between attempts, which is only
    observable if the attempts are scripted.
    """
    remaining = list(queued)

    def opener(url: str) -> Response:
        item = remaining.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    return opener


def _ok(payload: object) -> Response:
    return Response(200, REGISTRY_HEADERS, json.dumps(payload).encode("utf-8"))


def _status(code: int, headers: Mapping[str, str] | None = None) -> Response:
    return Response(code, headers or REGISTRY_HEADERS, b"")


def test_a_successful_response_is_decoded() -> None:
    result = http_fetch(
        "https://registry.test/v0/servers",
        opener=_responses(_ok({"servers": []})),
        sleep=lambda _: None,
    )

    assert result == {"servers": []}


def test_a_server_error_is_retried_until_it_succeeds() -> None:
    slept: list[float] = []

    result = http_fetch(
        "https://registry.test/v0/servers",
        opener=_responses(_status(503), _status(500), _ok({"servers": [1]})),
        sleep=slept.append,
    )

    assert result == {"servers": [1]}
    assert slept == [1.0, 2.0]


def test_a_dropped_connection_is_retried() -> None:
    result = http_fetch(
        "https://registry.test/v0/servers",
        opener=_responses(OSError("connection reset by peer"), _ok({"servers": []})),
        sleep=lambda _: None,
    )

    assert result == {"servers": []}


def test_retry_after_overrides_the_backoff_schedule() -> None:
    slept: list[float] = []

    http_fetch(
        "https://registry.test/v0/servers",
        opener=_responses(_status(429, {"retry-after": "7"}), _ok({"servers": []})),
        sleep=slept.append,
    )

    assert slept == [7.0]


def test_an_absurd_retry_after_is_capped() -> None:
    slept: list[float] = []

    http_fetch(
        "https://registry.test/v0/servers",
        opener=_responses(_status(429, {"retry-after": "86400"}), _ok({"servers": []})),
        sleep=slept.append,
    )

    assert slept == [60.0]


def test_a_client_error_is_not_retried() -> None:
    opener = _responses(_status(404))

    with pytest.raises(FetchFailed, match="404"):
        http_fetch("https://registry.test/v0/servers", opener=opener, sleep=lambda _: None)


def test_giving_up_names_the_url_and_the_attempt_count() -> None:
    opener = _responses(*[_status(500)] * 4)

    with pytest.raises(FetchFailed, match=r"registry\.test.*4 attempts"):
        http_fetch(
            "https://registry.test/v0/servers",
            opener=opener,
            sleep=lambda _: None,
            max_attempts=4,
        )


def test_a_body_that_is_not_json_is_reported_as_a_failure() -> None:
    opener = _responses(Response(200, REGISTRY_HEADERS, b"<html>maintenance</html>"))

    with pytest.raises(FetchFailed, match="not JSON"):
        http_fetch("https://registry.test/v0/servers", opener=opener, sleep=lambda _: None)


def test_an_http_error_from_urllib_becomes_a_response() -> None:
    """urlopen raises 4xx and 5xx rather than returning them.

    Without this conversion the real opener would raise HTTPError, which
    subclasses OSError, so every 404 would be retried as though it were a
    dropped connection and no Retry-After would ever be read. Neither is
    visible through an injected opener, which is why this tests the real one.
    """
    error = urllib.error.HTTPError(
        url="https://registry.test/v0/servers",
        code=429,
        msg="Too Many Requests",
        hdrs=email.message_from_string("Retry-After: 3"),
        fp=io.BytesIO(b"slow down"),
    )

    response = _as_response(error)

    assert response.status == 429
    assert response.headers["retry-after"] == "3"
    assert response.body == b"slow down"
