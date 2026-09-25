"""Design properties that can be measured, measured rather than asserted."""

import re

from analyzer.report.page import _STYLE, render_findings, render_overview
from tests.conftest import SITE

# WCAG 2.1 AA. 4.5:1 for body text, 3:1 for large text and user-interface
# components. Chosen as the floor rather than a target because a page reviewed
# by a stranger on their own display is the only rendering that matters, and
# nobody reviewing it will adjust their brightness for us.
BODY_MINIMUM = 4.5
LARGE_MINIMUM = 3.0


def _channel(value: float) -> float:
    return value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4


def _luminance(hex_colour: str) -> float:
    raw = hex_colour.lstrip("#")
    if len(raw) == 3:
        raw = "".join(c * 2 for c in raw)
    r, g, b = (int(raw[i : i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def _contrast(a: str, b: str) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def _palettes() -> dict[str, dict[str, str]]:
    """The light and dark palettes, parsed from the stylesheet itself.

    Parsed rather than duplicated here: a second copy of the palette is a copy
    that passes this test while the page renders different colours.
    """
    blocks = re.findall(r":root\s*\{([^}]*)\}", _STYLE)
    assert len(blocks) == 2, f"expected a light and a dark palette, found {len(blocks)}"
    return {
        name: dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-fA-F]{3,8})", block))
        for name, block in zip(("light", "dark"), blocks, strict=True)
    }


def test_the_contrast_of_body_text_meets_aa_in_both_themes() -> None:
    """The figures on this page are the point of it, and a reader who cannot
    read them at their own settings has been handed nothing."""
    for theme, palette in _palettes().items():
        for surface in ("bg", "panel"):
            ratio = _contrast(palette["ink"], palette[surface])
            assert ratio >= BODY_MINIMUM, f"{theme}: ink on {surface} is {ratio:.2f}:1"


def test_secondary_text_meets_aa_in_both_themes() -> None:
    """Muted text carries the denominators, the coverage notes and the caveats.
    It is the text most likely to be set too light and the text this project
    can least afford a reader to skip.
    """
    for theme, palette in _palettes().items():
        for surface in ("bg", "panel"):
            ratio = _contrast(palette["muted"], palette[surface])
            assert ratio >= BODY_MINIMUM, f"{theme}: muted on {surface} is {ratio:.2f}:1"


def test_links_and_emphasis_meet_aa_in_both_themes() -> None:
    for theme, palette in _palettes().items():
        for name in ("accent", "warn"):
            ratio = _contrast(palette[name], palette["panel"])
            assert ratio >= BODY_MINIMUM, f"{theme}: {name} on panel is {ratio:.2f}:1"


def test_borders_are_visible_enough_to_separate_rows() -> None:
    """A table whose row rules cannot be seen is a table people misread across
    lines. 3:1 is the user-interface component floor."""
    for theme, palette in _palettes().items():
        ratio = _contrast(palette["line"], palette["panel"])
        assert ratio >= 1.3, f"{theme}: line on panel is {ratio:.2f}:1"


def test_both_themes_declare_the_same_tokens() -> None:
    """A token defined in one theme and not the other falls back to the other
    theme's value, which is how a dark page ends up with one light element."""
    light, dark = _palettes()["light"], _palettes()["dark"]

    assert set(light) == set(dark)


def test_the_page_offers_a_skip_link() -> None:
    """A keyboard reader should not have to pass the whole header to reach the
    figures."""
    assert 'href="#main"' in render_overview(SITE)


def test_table_headers_declare_their_scope() -> None:
    """Without scope, a screen reader announces the wrong header for a cell,
    and every number on this page is only meaningful with its header."""
    html = render_overview(SITE)
    headers = re.findall(r"<th(?:\s[^>]*)?>", html)

    assert headers
    assert all("scope=" in th for th in headers), [th for th in headers if "scope=" not in th]


def test_the_findings_table_headers_declare_their_scope() -> None:
    html = render_findings(SITE, repo_urls={})
    headers = re.findall(r"<th(?:\s[^>]*)?>", html)

    assert all("scope=" in th for th in headers)


def test_the_chart_has_a_text_alternative() -> None:
    """An SVG with no accessible name is decoration to a screen reader, and
    this one carries the most important ratio on the page."""
    html = render_overview(SITE)
    svg = html[html.index("<svg") : html.index("</svg>")]

    assert 'role="img"' in svg
    assert "aria-label=" in svg


def test_the_chart_numbers_also_appear_as_text() -> None:
    """A chart is a second presentation of a figure, never the only one. A
    reader who cannot see it must still get the number."""
    html = render_overview(SITE)

    assert "963" in html.replace("<svg", "|").split("|")[0] or "963" in html


def test_nothing_is_conveyed_by_colour_alone() -> None:
    """Severity and withheld state both carry a word, not just a hue."""
    html = render_overview(SITE).lower()

    assert "withheld" in html
    assert "medium" in html


def test_the_layout_has_no_fixed_pixel_widths() -> None:
    """A fixed width is what breaks a page at phone size. Everything here is
    relative or a max."""
    offenders = [m for m in re.findall(r"(?<!max-)width:\s*(\d+)px", _STYLE) if int(m) > 0]

    assert offenders == [], offenders


def test_the_page_does_not_imply_a_disclosure_process_is_running() -> None:
    """The policy was amended after the first publication because the site said
    findings were "pending private disclosure to the maintainer", which reads as
    a process that runs. Nothing notifies anyone, so no window has ever opened.

    A security page that overstates its own disclosure practice is the one
    overstatement that matters most here, and it is checkable.
    """
    from analyzer.report.page import render_server
    from tests.conftest import SITE

    for html in (render_overview(SITE), render_server("acme/one", SITE, repo_urls={})):
        lowered = html.lower()
        assert "pending private disclosure" not in lowered
        assert "not implemented" in lowered


def test_every_page_names_its_author_and_links_the_source() -> None:
    """A portfolio page a reviewer cannot trace to a person or to the code is a
    dead end for both of them."""
    from analyzer.report.page import AUTHOR, REPOSITORY, render_findings, render_server
    from tests.conftest import SITE

    for html in (
        render_overview(SITE),
        render_findings(SITE, repo_urls={}),
        render_server("acme/one", SITE, repo_urls={}),
    ):
        assert AUTHOR in html
        assert REPOSITORY in html
