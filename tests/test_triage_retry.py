"""Transient upstream failures, which a long run will meet.

Written after a real one: a 502 on the first paid call of a 210-call experiment
aborted the whole run. Nothing was lost, because answers are cached as they are
made, but a run that cannot survive one bad gateway cannot be completed at all.
"""

import io
import urllib.error
from typing import Any

import pytest

from analyzer.triage.jev import MAX_ATTEMPTS, is_transient, post_json


def _http_error(code: int, body: bytes = b"upstream said no") -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://example.invalid/decide", code, "err", {}, io.BytesIO(body)  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("code", [429, 500, 502, 503, 504])
def test_a_transient_status_is_worth_retrying(code: int) -> None:
    """These say "ask again", not "your request is wrong"."""
    assert is_transient(_http_error(code))


@pytest.mark.parametrize("code", [400, 401, 402, 403, 404, 422])
def test_a_permanent_status_is_not_retried(code: int) -> None:
    """Retrying an unauthorised or malformed request wastes time and, where the
    request is billable, money - and it delays the report of a fault that will
    not fix itself."""
    assert not is_transient(_http_error(code))


def test_a_network_failure_is_transient() -> None:
    """A dropped connection or a timeout is the commonest interruption over a
    run of several hundred calls, and it carries no status at all."""
    assert is_transient(urllib.error.URLError("connection reset"))


def test_a_transient_failure_is_retried_and_the_answer_returned() -> None:
    attempts: list[int] = []

    def send(_request: Any) -> dict[str, Any]:
        attempts.append(1)
        if len(attempts) == 1:
            raise _http_error(502)
        return {"answers": {"k": {"noul": 0.9}}}

    result = post_json(
        "https://example.invalid/decide",
        {"state": "x"},
        send=send,
        sleep=lambda _seconds: None,
        token="test-token",
    )

    assert result == {"answers": {"k": {"noul": 0.9}}}
    assert len(attempts) == 2


def test_a_permanent_failure_is_attempted_exactly_once() -> None:
    attempts: list[int] = []

    def send(_request: Any) -> dict[str, Any]:
        attempts.append(1)
        raise _http_error(400, b"state too large")

    with pytest.raises(RuntimeError, match="state too large"):
        post_json(
            "https://example.invalid/decide",
            {"state": "x"},
            send=send,
            sleep=lambda _seconds: None,
            token="test-token",
        )

    assert len(attempts) == 1


def test_retries_are_bounded_and_the_failure_says_how_many_were_made() -> None:
    """An unbounded retry against an outage is a run that never ends and a bill
    that never stops. The count belongs in the message, because "it failed"
    and "it failed five times over ninety seconds" call for different actions.
    """
    attempts: list[int] = []

    def send(_request: Any) -> dict[str, Any]:
        attempts.append(1)
        raise _http_error(503)

    with pytest.raises(RuntimeError, match=f"{MAX_ATTEMPTS} attempts"):
        post_json(
            "https://example.invalid/decide",
            {"state": "x"},
            send=send,
            sleep=lambda _seconds: None,
            token="test-token",
        )

    assert len(attempts) == MAX_ATTEMPTS


def test_backoff_grows_rather_than_hammering_a_service_that_is_already_failing() -> None:
    """A fixed short delay against a rate limit re-triggers the rate limit."""
    waits: list[float] = []

    def send(_request: Any) -> dict[str, Any]:
        raise _http_error(429)

    with pytest.raises(RuntimeError):
        post_json(
            "https://example.invalid/decide",
            {"state": "x"},
            send=send,
            sleep=waits.append,
            token="test-token",
        )

    assert len(waits) == MAX_ATTEMPTS - 1
    assert waits == sorted(waits) and waits[0] < waits[-1]


def test_an_empty_balance_keeps_its_own_message_and_is_not_retried() -> None:
    """The one status where the operator has to do something, so it must not be
    buried under a retry loop or a generic message."""
    attempts: list[int] = []

    def send(_request: Any) -> dict[str, Any]:
        attempts.append(1)
        raise _http_error(402)

    with pytest.raises(RuntimeError, match="prepaid balance"):
        post_json(
            "https://example.invalid/decide",
            {"state": "x"},
            send=send,
            sleep=lambda _seconds: None,
            token="test-token",
        )

    assert len(attempts) == 1
