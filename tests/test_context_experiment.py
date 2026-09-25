"""The comparison the paper rests on, computed rather than eyeballed."""

import pytest

from evals.harness.experiment import ConditionResult, compare_conditions


def _entry(entry_id: str, window: str | None, function: str | None) -> dict[str, object]:
    observations: dict[str, object] = {}
    if window:
        observations["window"] = {"label": window, "reason": "x", "labelled_by": "model"}
    if function:
        observations["function"] = {"label": function, "reason": "x", "labelled_by": "model"}
    return {"entry_id": entry_id, "rule_id": "SHELL-EXEC-UNSAFE", "observations": observations}


def test_the_unsure_rate_is_reported_per_condition() -> None:
    """The first half of the claim: a narrow window leaves more findings
    undecidable."""
    entries = [
        _entry("a", "unsure", "true_positive"),
        _entry("b", "unsure", "false_positive"),
        _entry("c", "false_positive", "false_positive"),
        _entry("d", "true_positive", "true_positive"),
    ]

    window, function = compare_conditions(entries)

    assert window.unsure == 2
    assert function.unsure == 0


def test_precision_is_computed_over_decided_entries_only() -> None:
    """An entry nobody could decide is evidence about the context, not about
    the rule, so it belongs in the unsure rate and not in the denominator."""
    entries = [
        _entry("a", "unsure", "true_positive"),
        _entry("b", "false_positive", "false_positive"),
        _entry("c", "true_positive", "true_positive"),
    ]

    window, function = compare_conditions(entries)

    assert window.decided == 2
    assert window.precision == pytest.approx(0.5)
    assert function.decided == 3
    assert function.precision == pytest.approx(2 / 3)


def test_the_entries_that_became_decidable_are_counted_separately() -> None:
    """This is the mechanism, and the whole argument turns on it: if the
    findings a narrow window hides are disproportionately true positives, then
    narrowing the context cannot raise measured precision - it can only lower
    it. A count of the flips is what makes that checkable rather than asserted.
    """
    entries = [
        _entry("a", "unsure", "true_positive"),
        _entry("b", "unsure", "true_positive"),
        _entry("c", "unsure", "false_positive"),
        _entry("d", "false_positive", "false_positive"),
    ]

    _, _ = compare_conditions(entries)
    from evals.harness.experiment import resolved_by_context

    flips = resolved_by_context(entries)

    assert flips.resolved == 3
    assert flips.true_positives == 2
    assert flips.share_true == pytest.approx(2 / 3)


def test_an_entry_judged_under_only_one_condition_is_excluded() -> None:
    """A within-subject comparison needs both observations. Counting an entry
    judged once would compare different samples and call it a condition
    effect."""
    entries = [
        _entry("a", "unsure", "true_positive"),
        _entry("b", "false_positive", None),
        _entry("c", None, "true_positive"),
    ]

    window, function = compare_conditions(entries)

    assert window.n == 1
    assert function.n == 1


def test_a_condition_with_nothing_decided_reports_no_precision() -> None:
    """Zero over zero is not zero precision, and printing 0.00 would state a
    measurement that was never made."""
    entries = [_entry("a", "unsure", "unsure")]

    window, function = compare_conditions(entries)

    assert window.precision is None
    assert function.precision is None


def test_the_result_carries_its_own_sample_size() -> None:
    """A precision without its n is the figure this project refuses to
    publish anywhere else."""
    entries = [_entry("a", "true_positive", "true_positive")]

    window, _ = compare_conditions(entries)

    assert isinstance(window, ConditionResult)
    assert window.n == 1


def test_a_function_shorter_than_its_window_is_reported_as_suspect() -> None:
    """The standing check for the bug that produced this experiment's first
    broken capture.

    A finding carries no column, so a function node overlapping the flagged line
    can be a fragment of it rather than the scope around it. That produced ten
    characters of unrelated code as one finding's "enclosing function", and the
    only reason it was caught is that the size distribution was looked at by
    hand. An enclosing function is normally larger than a window centred on the
    same line, so one that is dramatically smaller is the signature of that
    failure - and a signature nobody computes is not a check.
    """
    from evals.harness.experiment import suspect_functions

    entries: list[dict[str, object]] = [
        {"entry_id": "a", "context": "x" * 1000, "context_function": "() => null"},
        {"entry_id": "b", "context": "x" * 1000, "context_function": "x" * 1400},
        {"entry_id": "c", "context": "x" * 1000, "context_function": "x" * 900},
        {"entry_id": "d", "context": "x" * 1000},
    ]

    suspect = suspect_functions(entries)

    # "c" is smaller but plausibly a real short handler; "a" is two orders out.
    assert [entry_id for entry_id, _ in suspect] == ["a"]
    assert suspect[0][1] < 0.05


def test_an_entry_with_no_function_is_not_suspect() -> None:
    """A rule the manipulation does not apply to has no second condition, which
    is the intended state rather than a missing capture."""
    from evals.harness.experiment import suspect_functions

    assert suspect_functions([{"entry_id": "a", "context": "x" * 100}]) == []
