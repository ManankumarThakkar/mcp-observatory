import json

import pytest

from analyzer.crawler.http import Response
from analyzer.report.channels import ChannelLookupFailed, suggest_channel

API = "https://api.github.com/repos/acme/notes"


def _opener(answers: dict[str, tuple[int, object]]):  # type: ignore[no-untyped-def]
    seen: list[str] = []

    def opener(url: str) -> Response:
        seen.append(url)
        status, body = answers.get(url, (404, {"message": "Not Found"}))
        return Response(status=status, headers={}, body=json.dumps(body).encode())

    opener.seen = seen  # type: ignore[attr-defined]
    return opener


def test_private_reporting_is_preferred_when_enabled() -> None:
    opener = _opener({f"{API}/private-vulnerability-reporting": (200, {"enabled": True})})
    suggestion = suggest_channel("https://github.com/acme/notes", opener)
    assert suggestion is not None
    assert suggestion.channel == "private_advisory"
    assert suggestion.url == "https://github.com/acme/notes/security/advisories/new"


def test_a_security_policy_is_next_wherever_github_looks_for_one() -> None:
    page = "https://github.com/acme/notes/blob/main/.github/SECURITY.md"
    opener = _opener(
        {
            f"{API}/private-vulnerability-reporting": (200, {"enabled": False}),
            f"{API}/contents/.github/SECURITY.md": (200, {"html_url": page}),
        }
    )
    suggestion = suggest_channel("https://github.com/acme/notes", opener)
    assert suggestion is not None
    assert (suggestion.channel, suggestion.url) == ("security_contact", page)


def test_with_neither_the_draft_asks_for_a_contact() -> None:
    opener = _opener({f"{API}/private-vulnerability-reporting": (200, {"enabled": False})})
    suggestion = suggest_channel("https://github.com/acme/notes", opener)
    assert suggestion is not None
    assert suggestion.channel == "contact_request"


def test_an_error_is_raised_not_read_as_no_private_channel() -> None:
    # Falling through on a rate limit would suggest the least private channel,
    # a public issue, for a server whose private reporting may well be on.
    opener = _opener({f"{API}/private-vulnerability-reporting": (403, {"message": "rate limited"})})
    with pytest.raises(ChannelLookupFailed, match="403"):
        suggest_channel("https://github.com/acme/notes", opener)


def test_a_repository_not_on_github_cannot_be_checked() -> None:
    opener = _opener({})
    assert suggest_channel("https://gitlab.com/acme/notes", opener) is None
    assert opener.seen == []
