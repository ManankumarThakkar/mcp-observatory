from analyzer.triage.base import (
    FLAGGED_MARKER,
    MAX_LINE_CHARS,
    MAX_WINDOW_CHARS,
    TRUNCATION_MARKER,
    as_condition,
    present,
)


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


def test_projecting_an_entry_onto_the_function_condition_moves_its_marker() -> None:
    """The second condition is applied by rewriting the entry, not by asking
    the presenter for a variant.

    Everything downstream - the presenter, the adjudication cache key, each
    model arm - then sees an ordinary entry and cannot treat one condition
    differently from the other. That is the property the comparison needs: a
    difference in the result has to come from the context, and an arm with a
    `condition` parameter is an arm that could branch on it.

    The offset moves with the text because the function begins at a different
    line of the file than the window does. Marking the window's index inside
    the function would put the marker on unrelated code, and the labeller would
    answer about code nobody flagged while the comparison still reported two
    contexts.
    """
    entry = {
        "context": "const a = 1",
        "flagged_offset": 0,
        "context_function": "function f(p) {\n  const q = p;\n  run(q);\n}",
        "flagged_offset_function": 2,
    }

    shown = present(as_condition(entry, "function"))

    marked = [line for line in shown.splitlines() if line.startswith(FLAGGED_MARKER)]
    assert len(marked) == 1
    assert "run(q)" in marked[0]


def test_the_two_conditions_key_the_adjudication_cache_differently() -> None:
    """Without this the second condition would be answered from the first
    condition's cached verdict, and the experiment would report that context
    makes no difference because it never asked twice."""
    from analyzer.triage.cache import cache_key

    entry = {
        "context": "const a = 1",
        "flagged_offset": 0,
        "context_function": "function f(p) {\n  const q = p;\n  run(q);\n}",
        "flagged_offset_function": 2,
        "rule_id": "SHELL-EXEC-UNSAFE",
        "language": "typescript",
    }

    window = cache_key("jev", as_condition(entry, "window"))
    function = cache_key("jev", as_condition(entry, "function"))

    assert window != function


def test_projecting_onto_a_condition_the_entry_lacks_is_refused() -> None:
    """Silently falling back to the window would record two observations of one
    context and publish them as a comparison between two, which is the single
    result this experiment must not produce."""
    import pytest

    entry = {"context": "const a = 1", "flagged_offset": 0}

    with pytest.raises(KeyError):
        as_condition(entry, "function")


def test_the_window_projection_leaves_the_entry_as_it_stands() -> None:
    """The first condition must be the entry exactly as every other consumer
    already sees it, or the comparison has two manipulations in it."""
    entry = {
        "context": "const a = 1",
        "flagged_offset": 0,
        "context_function": "function f() {}",
        "flagged_offset_function": 0,
    }

    assert present(as_condition(entry, "window")) == present(entry)
