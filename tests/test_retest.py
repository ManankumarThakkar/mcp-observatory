"""The judge asked the same question twice: the noise floor every flip rate needs."""

from typing import Any

import pytest

from evals.harness.retest import flip_overlap, retest_stability


def _e(entry_id: str, window: float | None = None, function: float | None = None) -> dict[str, Any]:
    probabilities: dict[str, float] = {}
    if window is not None:
        probabilities["window"] = window
    if function is not None:
        probabilities["function"] = function
    return {"entry_id": entry_id, "probabilities": probabilities}


def test_identical_runs_show_no_change() -> None:
    run = [_e("a", 0.8, 0.2), _e("b", 0.3, 0.3)]

    result = retest_stability(run, run)

    assert result["window"].verdict_changes == 0
    assert result["window"].identical == 2
    assert result["window"].max_shift == 0.0


def test_a_verdict_that_crosses_the_midpoint_counts_as_a_change() -> None:
    """A shift inside one side of 0.5 moves a probability, not a verdict. Only a
    crossing changes what a benchmark would publish."""
    first = [_e("a", window=0.52), _e("b", window=0.70)]
    second = [_e("a", window=0.48), _e("b", window=0.75)]

    result = retest_stability(first, second)["window"]

    assert result.verdict_changes == 1
    assert result.n == 2
    assert result.share == pytest.approx(0.5)
    assert result.max_shift == pytest.approx(0.05)
    assert result.identical == 0


def test_an_entry_asked_in_only_one_run_is_excluded() -> None:
    """Stability is a paired measurement: an answer with no second answer to compare
    against says nothing about it."""
    first = [_e("a", window=0.8), _e("b", window=0.8)]
    second = [_e("a", window=0.8)]

    assert retest_stability(first, second)["window"].n == 1


def test_a_condition_missing_from_both_runs_is_absent_rather_than_zero() -> None:
    """Zero changes out of zero items is not stability; it is no measurement."""
    run = [_e("a", window=0.8)]

    assert "function" not in retest_stability(run, run)


def test_the_flip_sets_of_two_runs_are_compared() -> None:
    """Whether the same findings flip in both runs is what separates a property of
    the findings from noise that happens to land at the same rate."""
    first = [_e("a", 0.8, 0.2), _e("b", 0.8, 0.2), _e("c", 0.8, 0.8)]
    second = [_e("a", 0.8, 0.2), _e("b", 0.8, 0.8), _e("c", 0.8, 0.2)]

    overlap = flip_overlap(first, second)

    assert (overlap.both, overlap.only_first, overlap.only_second) == (1, 1, 1)
    assert overlap.jaccard == pytest.approx(1 / 3)
