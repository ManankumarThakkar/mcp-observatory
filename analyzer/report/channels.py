"""Which private channel a maintainer can be reached on, checked read-only.

The approved order: GitHub private vulnerability reporting, then the contact in
a SECURITY.md, then a public issue asking only for a contact. Nothing here
sends or files anything; it only reads, so a person can choose with the facts
in front of them.
"""

import json
import re
from dataclasses import dataclass

from analyzer.crawler.http import Opener
from analyzer.report.ledger import Channel

API = "https://api.github.com/repos"

# Where GitHub itself looks for a security policy.
POLICY_PATHS = ("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md")

GITHUB_REPO = re.compile(r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


class ChannelLookupFailed(RuntimeError):
    """GitHub gave an answer that is neither yes nor no."""


@dataclass(frozen=True)
class ChannelSuggestion:
    channel: Channel
    url: str


def _ask(opener: Opener, url: str) -> dict[str, object] | None:
    """The JSON at `url`, None for "not there", and a refusal for anything else.

    Anything else is raised rather than read as absent. Falling through on a
    rate limit would suggest a public issue for a server whose private
    reporting may well be on, and the public channel is the one to avoid.
    """
    response = opener(url)
    if response.status == 404:
        return None
    if response.status != 200:
        raise ChannelLookupFailed(f"{url} returned HTTP {response.status}")
    payload = json.loads(response.body)
    return payload if isinstance(payload, dict) else None


def suggest_channel(repo_url: str, opener: Opener) -> ChannelSuggestion | None:
    """The best channel GitHub reports for this repository, or None off GitHub."""
    match = GITHUB_REPO.match(repo_url)
    if match is None:
        return None
    owner, repo = match.groups()
    reporting = _ask(opener, f"{API}/{owner}/{repo}/private-vulnerability-reporting")
    if reporting is not None and reporting.get("enabled") is True:
        return ChannelSuggestion(
            "private_advisory", f"https://github.com/{owner}/{repo}/security/advisories/new"
        )
    for path in POLICY_PATHS:
        policy = _ask(opener, f"{API}/{owner}/{repo}/contents/{path}")
        if policy is not None:
            return ChannelSuggestion("security_contact", str(policy.get("html_url", "")))
    return ChannelSuggestion("contact_request", f"https://github.com/{owner}/{repo}/issues/new")
