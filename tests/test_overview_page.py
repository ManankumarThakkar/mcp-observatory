import re

from analyzer.report.page import render_overview
from analyzer.report.site import CoverageRow, Decision, RuleSummary, SiteData

SITE = SiteData(
    generated_at="2026-09-25T01:10:58Z",
    published_at="2026-09-25T01:12:00Z",
    tool_version="0.1.0",
    corpus=21492,
    sampled=2000,
    sample_seed=20260923,
    scanned=1643,
    skipped=357,
    failed=0,
    findings_found=1285,
    findings_published=322,
    decisions_published=164,
    servers_affected=145,
    withheld=963,
    by_severity={"medium": 322},
    rules=(
        RuleSummary("SCOPE-OVERBROAD", "Server reach wider than its tools require", "Wide reach.",
                    ("typescript", "tsx"), 322, 164, 145),
        RuleSummary("TOOL-DESC-INJECTION", "Instructions planted in tool metadata", "Planted text.",
                    ("typescript", "tsx"), 0, 0, 0),
    ),
    coverage=(
        CoverageRow("SCOPE-OVERBROAD", "Server reach wider than its tools require", ("typescript", "tsx")),
        CoverageRow("UNICODE-CONCEAL", "Characters hidden from human review", ("*",)),
    ),
    groups=(
        Decision("acme/one", "SCOPE-OVERBROAD", "medium", "accepts any origin (*)", 16,
                 ("src/a.ts:1",), "2026-09-23T00:00:00Z", "2026-09-25T00:00:00Z"),
    ),
)


def test_the_denominator_appears_beside_the_scanned_count() -> None:
    """1,643 of 21,492 is 7.6%. The numerator alone is the figure a reviewer
    asks about within seconds, and omitting it reads as evasion."""
    html = render_overview(SITE)

    assert "21,492" in html
    assert "1,643" in html


def test_the_sampling_seed_is_published_so_the_set_can_be_regenerated() -> None:
    """The method is only a method if a reader can re-run it."""
    assert "20260923" in render_overview(SITE)


def test_what_was_found_is_stated_not_only_what_was_published() -> None:
    """322 published of 1,285 found. A page showing 322 alone reports a quarter
    of the result and reads as a far cleaner ecosystem than the one measured."""
    html = render_overview(SITE)

    assert "1,285" in html
    assert "322" in html
    assert "963" in html


def test_decisions_are_shown_rather_than_row_counts_alone() -> None:
    """322 rows are 164 things to fix. Presenting rows as problems overstates
    the count roughly twofold."""
    assert "164" in render_overview(SITE)


def test_the_page_says_accuracy_is_not_yet_measured() -> None:
    """The differentiator is a measured error rate, and it does not exist yet.
    A page that simply omits accuracy invites the reader to assume the findings
    are all real, which is the claim this project exists not to make.
    """
    html = render_overview(SITE).lower()

    assert "not yet measured" in html


def test_a_rule_that_published_nothing_is_still_listed_with_its_reason() -> None:
    """Four of five rules publish nothing because the gate withholds them. A
    table showing only what published would imply the others found nothing."""
    html = render_overview(SITE)

    assert "TOOL-DESC-INJECTION" in html
    assert "UNICODE-CONCEAL" in html


def test_per_language_coverage_is_on_the_page() -> None:
    """Success criterion 2a: stated alongside every aggregate figure, not
    linked away."""
    html = render_overview(SITE)

    assert "TypeScript" in html
    assert "every language" in html.lower()


def test_the_page_is_self_contained() -> None:
    """No fetch, no external script, no stylesheet request. It must render from
    file://, from a static host, and with no network at all - a dashboard that
    needs a server is not a static dashboard."""
    html = render_overview(SITE)

    assert "fetch(" not in html
    assert "<script src=" not in html
    assert "<link rel=\"stylesheet\"" not in html


def test_evidence_and_server_names_are_escaped() -> None:
    """Server ids and evidence come from repositories we do not control. An
    unescaped angle bracket in either is stored markup in a published page."""
    hostile = SiteData(
        **{
            **SITE.__dict__,
            "groups": (
                Decision('<script>alert(1)</script>', "SCOPE-OVERBROAD", "medium",
                         '"><img onerror=alert(1)>', 1, ("a.ts:1",), "x", "y"),
            ),
        }
    )

    html = render_overview(hostile)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_the_page_declares_a_language_and_a_title() -> None:
    """Accessibility and basic correctness: a screen reader needs both."""
    html = render_overview(SITE)

    assert re.search(r"<html[^>]+lang=", html)
    assert "<title>" in html


def test_dark_and_light_are_both_supported() -> None:
    """A page reviewed on somebody else's laptop at their settings."""
    assert "prefers-color-scheme" in render_overview(SITE)


def test_the_page_contains_no_stray_non_ascii_in_its_css() -> None:
    """A Devanagari six found its way into a hex colour, which would have
    shipped as an invalid custom property: the variable silently falls back and
    every muted element renders at the wrong contrast. CSS has no validator in
    this pipeline, so the check is here.
    """
    html = render_overview(SITE)
    style = html[html.index("<style>") : html.index("</style>")]
    stray = sorted({c for c in style if ord(c) > 127})

    assert stray == [], f"non-ascii in stylesheet: {[(c, hex(ord(c))) for c in stray]}"


def test_every_declared_colour_is_a_valid_hex_value() -> None:
    """The same defect class, caught positively rather than by exclusion."""
    import re

    html = render_overview(SITE)
    style = html[html.index("<style>") : html.index("</style>")]

    for name, value in re.findall(r"(--[a-z-]+):\s*([^;]+);", style):
        if value.strip().startswith("#"):
            assert re.fullmatch(r"#[0-9a-fA-F]{3,8}", value.strip()), f"{name}: {value!r}"
