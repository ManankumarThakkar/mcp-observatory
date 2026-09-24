import pytest

from evals.harness.benchmark import PRECISION_FLOOR, choose_threshold, sweep_thresholds

LABELS = [
    {"entry_id": "g-1", "rule_id": "R", "label": "true_positive"},
    {"entry_id": "g-2", "rule_id": "R", "label": "true_positive"},
    {"entry_id": "g-3", "rule_id": "R", "label": "false_positive"},
    {"entry_id": "g-4", "rule_id": "R", "label": "false_positive"},
]
SEPARABLE = {"g-1": 0.9, "g-2": 0.7, "g-3": 0.4, "g-4": 0.1}


def test_a_perfectly_separating_threshold_is_found() -> None:
    perfect = [p for p in sweep_thresholds(SEPARABLE, LABELS) if p.precision == 1.0 and p.recall == 1.0]

    assert perfect
    assert all(0.4 < p.threshold <= 0.7 for p in perfect)


def test_the_curve_covers_the_whole_range_so_a_reader_can_choose_differently() -> None:
    """D12 publishes what moving the threshold costs in either direction. That
    is the curve, and a curve with gaps cannot answer the question."""
    points = sweep_thresholds(SEPARABLE, LABELS, steps=11)

    assert len(points) == 11
    assert points[0].threshold == 0.0
    assert points[-1].threshold == pytest.approx(1.0)


def test_the_chosen_point_takes_the_most_recall_that_clears_the_floor() -> None:
    """Maximising F1 would trade a missed vulnerability against a false
    positive one for one, which is not the trade a tool that emails
    maintainers is making."""
    chosen = choose_threshold(sweep_thresholds(SEPARABLE, LABELS), floor=0.8)

    assert chosen.precision >= 0.8
    assert chosen.recall == 1.0


def test_no_threshold_clearing_the_floor_is_reported_rather_than_papered_over() -> None:
    """Lowering the bar to whatever the model managed makes the published
    precision a description of the model rather than a standard it met."""
    noisy = {"g-1": 0.5, "g-2": 0.5, "g-3": 0.5, "g-4": 0.5}

    with pytest.raises(ValueError, match="0.8"):
        choose_threshold(sweep_thresholds(noisy, LABELS), floor=0.8)


def test_a_threshold_is_a_floor_rather_than_a_strict_greater_than() -> None:
    """At a threshold of exactly 0.7, a decision of 0.7 counts as positive.
    The off-by-one silently shifts every published figure by one entry."""
    points = {p.threshold: p for p in sweep_thresholds(SEPARABLE, LABELS, steps=11)}

    assert points[0.7].recall == 1.0


def test_an_entry_with_no_decision_is_refused() -> None:
    """An arm that answered only some entries would otherwise be scored over
    the subset it chose."""
    with pytest.raises(ValueError, match="g-4"):
        sweep_thresholds({"g-1": 0.9, "g-2": 0.7, "g-3": 0.4}, LABELS)


def test_the_published_floor_is_the_documented_one() -> None:
    assert PRECISION_FLOOR == 0.80
