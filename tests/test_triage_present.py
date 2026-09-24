
from analyzer.triage.base import MAX_LINE_CHARS, MAX_WINDOW_CHARS, TRUNCATION_MARKER, present


def _entry(context: str, offset: int = 0) -> dict[str, object]:
    return {"context": context, "flagged_offset": offset}


def test_a_line_longer_than_the_cap_is_truncated_visibly() -> None:
    """A minified file or a one-line JSON export makes a single line enormous.
    The window is bounded in lines, not characters, so one line can be the
    whole file. Silently sending it costs tokens nobody agreed to and shows a
    labeller something no terminal can render.
    """
    shown = present(_entry("x" * 5000))

    assert len(shown) < 5000
    assert TRUNCATION_MARKER in shown


def test_truncation_keeps_the_start_of_the_line_where_the_code_is() -> None:
    shown = present(_entry("const dangerous = " + "y" * 5000))

    assert "const dangerous = " in shown


def test_a_line_within_the_cap_is_untouched() -> None:
    """Truncating everything would add noise to the 99% of windows that are
    ordinary source."""
    shown = present(_entry("const a = 1"))

    assert TRUNCATION_MARKER not in shown
    assert shown == "> const a = 1"


def test_the_whole_window_is_capped_even_when_every_line_is_short() -> None:
    """Twelve lines either side of a line in a file of thousands of short
    lines is fine, but the cap must not be defeated by many medium lines."""
    shown = present(_entry("\n".join("z" * 190 for _ in range(200))))

    assert len(shown) <= MAX_WINDOW_CHARS + len(TRUNCATION_MARKER) + 200


def test_the_flagged_line_survives_a_window_level_truncation() -> None:
    """Cutting the window must never remove the thing being asked about."""
    lines = ["z" * 190 for _ in range(200)]
    lines[150] = "exec(userInput)"
    shown = present(_entry("\n".join(lines), offset=150))

    assert "exec(userInput)" in shown


def test_the_caps_are_the_documented_ones() -> None:
    assert (MAX_LINE_CHARS, MAX_WINDOW_CHARS) == (200, 8_000)


def test_repeated_lines_in_a_window_are_all_kept() -> None:
    """A window legitimately contains repeated lines - a blank one, a lone
    closing brace. Collecting them into a set collapses them and misaligns
    every line count a reader makes, including the flagged offset.
    """
    shown = present(_entry("}\n}\n}", offset=1))

    assert shown.count("}") == 3
