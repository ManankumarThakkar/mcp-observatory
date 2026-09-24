import pytest

from evals.harness.score import Score, score_all, score_rule, weighted_precision

LABELS = [
    {"entry_id": "g-1", "rule_id": "R", "label": "true_positive"},
    {"entry_id": "g-2", "rule_id": "R", "label": "true_positive"},
    {"entry_id": "g-3", "rule_id": "R", "label": "false_positive"},
    {"entry_id": "g-4", "rule_id": "R", "label": "false_positive"},
]


def _predict(**verdicts: bool) -> list[dict[str, object]]:
    return [{"entry_id": k.replace("_", "-"), "verdict": v} for k, v in verdicts.items()]


def test_a_perfect_arm_scores_one() -> None:
    predictions = _predict(g_1=True, g_2=True, g_3=False, g_4=False)

    assert score_rule(predictions, LABELS) == Score("R", 1.0, 1.0, 1.0, 4)


def test_an_arm_that_says_yes_to_everything_has_full_recall_and_base_precision() -> None:
    """This is the rules-only baseline, and it is the number to beat. Its
    precision is the corpus base rate by construction."""
    score = score_rule(_predict(g_1=True, g_2=True, g_3=True, g_4=True), LABELS)

    assert score.recall == 1.0
    assert score.precision == 0.5


def test_unsure_labels_are_excluded_rather_than_counted_as_wrong() -> None:
    """An entry a human could not decide from the window is evidence about the
    window, not about the model."""
    labels = [*LABELS, {"entry_id": "g-5", "rule_id": "R", "label": "unsure"}]

    score = score_rule(_predict(g_1=True, g_2=True, g_3=True, g_4=True, g_5=True), labels)

    assert score.support == 4


def test_an_arm_that_predicts_nothing_true_scores_zero_rather_than_crashing() -> None:
    """Dividing by zero here would break the CI gate on precisely the run that
    needed to report the failure, hiding it behind a traceback."""
    score = score_rule(_predict(g_1=False, g_2=False, g_3=False, g_4=False), LABELS)

    assert (score.precision, score.recall, score.f1) == (0.0, 0.0, 0.0)


def test_a_prediction_for_an_entry_with_no_label_is_refused() -> None:
    """Ignoring it would shrink the denominator silently, which inflates every
    figure computed from it, and the inflation grows with how badly the two
    files disagree."""
    with pytest.raises(ValueError, match="g-99"):
        score_rule([*_predict(g_1=True), {"entry_id": "g-99", "verdict": True}], LABELS)


def test_a_label_with_no_prediction_is_refused() -> None:
    """An arm that answered only the easy entries would otherwise report a
    precision over the subset it chose to answer."""
    with pytest.raises(ValueError, match="g-4"):
        score_rule(_predict(g_1=True, g_2=True, g_3=False), LABELS)


def test_rules_are_scored_independently() -> None:
    labels = [
        *LABELS,
        {"entry_id": "g-9", "rule_id": "S", "label": "true_positive"},
    ]
    predictions = _predict(g_1=True, g_2=True, g_3=False, g_4=False, g_9=False)

    scores = score_all(predictions, labels)

    assert scores["R"].precision == 1.0
    assert scores["S"].recall == 0.0


def test_the_published_figure_weights_rules_by_their_real_volume() -> None:
    """The sample over-represents quiet rules on purpose, so the unweighted
    number describes the sample and not the corpus."""
    scores = {
        "LOUD": Score("LOUD", precision=0.5, recall=1.0, f1=0.67, support=60),
        "QUIET": Score("QUIET", precision=1.0, recall=1.0, f1=1.0, support=60),
    }

    assert weighted_precision(scores, {"LOUD": 9_000, "QUIET": 1_000}) == pytest.approx(0.55)


def test_weighting_against_an_unknown_population_is_refused() -> None:
    """Treating a missing count as zero would silently drop that rule from the
    headline figure, which is the one number most likely to be quoted alone."""
    scores = {"LOUD": Score("LOUD", 0.5, 1.0, 0.67, 60)}

    with pytest.raises(ValueError, match="LOUD"):
        weighted_precision(scores, {})
