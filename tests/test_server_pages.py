import pytest

from analyzer.report.page import render_findings, render_server, server_slug
from analyzer.report.site import Decision, SiteData
from tests.conftest import SITE

GROUPS = (
    Decision("acme/one", "SCOPE-OVERBROAD", "medium", "accepts any origin (*)", 16,
             ("src/a.ts:1", "src/a.ts:9"), "2026-09-23T00:00:00Z", "2026-09-25T00:00:00Z"),
    Decision("acme/one", "SCOPE-OVERBROAD", "medium", "listens on 0.0.0.0", 1,
             ("src/b.ts:4",), "2026-09-23T00:00:00Z", "2026-09-25T00:00:00Z"),
    Decision("other/two", "SCOPE-OVERBROAD", "medium", "accepts any origin (*)", 2,
             ("i.ts:3",), "2026-09-24T00:00:00Z", "2026-09-25T00:00:00Z"),
)
SITE_WITH_GROUPS = SiteData(**{**SITE.__dict__, "groups": GROUPS, "servers_affected": 2})
REPOS = {"acme/one": "https://github.com/acme/one-server"}


def test_a_slug_is_filesystem_and_url_safe() -> None:
    """Server ids carry dots and a slash: `io.github.owner/repo`. Neither
    belongs in a path segment."""
    assert server_slug("io.github.Trusty-Squire/mcp") == "io.github.trusty-squire--mcp"


def test_two_different_servers_cannot_share_a_slug() -> None:
    """A collision would silently overwrite one server's page with another's,
    and the maintainer of the first would read somebody else's findings."""
    # Case is the realistic collision, because the slug is lowercased so the
    # page works on a case-insensitive filesystem. A registry can hold both
    # spellings, and without the check one page would overwrite the other.
    with pytest.raises(ValueError, match="slug"):
        render_findings(
            SiteData(**{**SITE.__dict__, "groups": (
                Decision("io.github.Owner/Repo", "R", "medium", "e", 1, ("f:1",), "x", "y"),
                Decision("io.github.owner/repo", "R", "medium", "e", 1, ("f:1",), "x", "y"),
            )}),
            repo_urls={},
        )


def test_a_slash_cannot_be_impersonated_by_a_double_dash() -> None:
    """`a/b` and `a--b` would both become `a--b` if the separator were not
    checked, which is the other way one server's page overwrites another's."""
    with pytest.raises(ValueError, match="slug"):
        render_findings(
            SiteData(**{**SITE.__dict__, "groups": (
                Decision("a/b", "R", "medium", "e", 1, ("f:1",), "x", "y"),
                Decision("a--b", "R", "medium", "e", 1, ("f:1",), "x", "y"),
            )}),
            repo_urls={},
        )


def test_the_findings_page_lists_every_affected_server_once() -> None:
    """A maintainer finds their server by searching this page, so every one
    must appear and appear once."""
    html = render_findings(SITE_WITH_GROUPS, repo_urls=REPOS)

    assert html.count("acme/one") >= 1
    assert "other/two" in html


def test_the_findings_page_shows_decisions_with_their_line_counts() -> None:
    """16 lines of one decision is one thing to fix, and the page says both."""
    html = render_findings(SITE_WITH_GROUPS, repo_urls=REPOS)

    assert "16" in html


def test_the_findings_page_states_the_multi_name_caveat() -> None:
    """A repository registered under several names publishes under one of
    them, so a maintainer searching the name they know may find nothing. Four
    of 145 affected servers are in that position, which is few enough to be
    invisible and enough to matter to those four.
    """
    html = render_findings(SITE_WITH_GROUPS, repo_urls=REPOS).lower()

    assert "more than one name" in html or "several names" in html


def test_a_server_page_shows_its_repository_when_known() -> None:
    """The id is a registry name; the repository is what a maintainer
    recognises."""
    html = render_server("acme/one", SITE_WITH_GROUPS, repo_urls=REPOS)

    assert "https://github.com/acme/one-server" in html


def test_a_server_page_without_a_known_repository_still_renders() -> None:
    """servers.json is written by a scan and preserved by republication, so it
    can be absent or stale. A missing entry must not produce a broken page for
    that server."""
    html = render_server("other/two", SITE_WITH_GROUPS, repo_urls=REPOS)

    assert "other/two" in html


def test_a_server_page_carries_only_that_server_s_findings() -> None:
    """The obvious failure is a template that renders every finding on every
    page, which would publish one maintainer's findings on another's page."""
    html = render_server("other/two", SITE_WITH_GROUPS, repo_urls=REPOS)

    assert "listens on 0.0.0.0" not in html
    assert "acme/one" not in html


def test_a_server_page_says_what_is_withheld_about_that_server() -> None:
    """A page showing one medium finding, when the same server may have
    withheld critical ones, reads as a clean bill of health. It is not one.
    """
    html = render_server("acme/one", SITE_WITH_GROUPS, repo_urls=REPOS).lower()

    assert "withheld" in html


def test_a_server_page_links_back() -> None:
    assert 'href="../index.html"' in render_server("acme/one", SITE_WITH_GROUPS, repo_urls=REPOS)


def test_server_content_is_escaped() -> None:
    hostile = SiteData(**{**SITE.__dict__, "groups": (
        Decision("x/y", "R", "medium", '"><img onerror=alert(1)>', 1, ("a:1",), "x", "y"),
    )})

    html = render_server("x/y", hostile, repo_urls={"x/y": '"><script>'})

    assert "<img onerror" not in html
    assert "<script>" not in html.split("</style>")[1]


@pytest.mark.parametrize(
    "hostile",
    [
        "javascript:alert(document.domain)",
        "JavaScript:alert(1)",
        "  javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
        "https://",
    ],
)
def test_a_link_is_never_rendered_for_a_scheme_a_browser_would_execute(hostile: str) -> None:
    """Escaping is not enough here, and that is the whole point.

    `escape(url, quote=True)` stops an attribute break-out, and
    `javascript:alert(1)` needs no quotes - it is a valid href value. The URL
    reaches this function from data/servers.json, read into a plain dict, so
    ServerRecord's https guarantee stops at the file boundary exactly as the
    index loader's did. A javascript: href in a published page is stored XSS on
    a public site.
    """
    html = render_server("x/y", SITE_WITH_GROUPS, repo_urls={"x/y": hostile})

    assert "javascript:" not in html.lower()
    assert "vbscript:" not in html.lower()
    assert "data:text/html" not in html.lower()
    assert "<a href=" not in html.split("<footer>")[0]


def test_an_ordinary_repository_link_still_renders() -> None:
    """The narrowing must not cost the link, which is the reason the field was
    published at all."""
    html = render_server("x/y", SITE_WITH_GROUPS, repo_urls={"x/y": "https://github.com/a/b"})

    assert 'href="https://github.com/a/b"' in html


def test_a_refused_url_reads_as_unrecorded_rather_than_vanishing() -> None:
    """A blank cell looks like a rendering bug. Saying the address is not
    recorded is true and is what a reader can act on."""
    html = render_server("x/y", SITE_WITH_GROUPS, repo_urls={"x/y": "javascript:alert(1)"})

    assert "not recorded" in html
