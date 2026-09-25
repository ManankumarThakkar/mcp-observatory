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


def test_entries_split_into_the_predicted_and_the_control_group() -> None:
    """The partition is derived from the rules, not written out here.

    Which rules a wider context is predicted to help is recorded on the rules
    themselves, for reasons that predate this experiment: a taint rule asks
    whether a value an assistant supplies reaches a sink, and that question
    spans the function. Deriving the split means widening the prediction
    requires changing the rule, and the analysis follows - rather than two lists
    that can disagree once the numbers are visible.
    """
    from evals.harness.experiment import split_by_prediction

    entries = [
        {"entry_id": "a", "rule_id": "SHELL-EXEC-UNSAFE"},
        {"entry_id": "b", "rule_id": "PATH-TRAVERSAL"},
        {"entry_id": "c", "rule_id": "UNICODE-CONCEAL"},
        {"entry_id": "d", "rule_id": "SCOPE-OVERBROAD"},
    ]

    predicted, control = split_by_prediction(entries)

    assert {e["entry_id"] for e in predicted} == {"a", "b"}
    assert {e["entry_id"] for e in control} == {"c", "d"}


def test_the_prediction_comes_from_the_rules_themselves() -> None:
    """A test that iterates the declaration rather than restating it, so
    widening a rule's prediction cannot leave the analysis behind."""
    from analyzer.rules import ALL_RULES
    from evals.harness.experiment import split_by_prediction

    entries = [{"entry_id": rule.rule_id, "rule_id": rule.rule_id} for rule in ALL_RULES]
    predicted, control = split_by_prediction(entries)

    expected = {r.rule_id for r in ALL_RULES if r.needs_enclosing_function}
    assert {e["entry_id"] for e in predicted} == expected
    assert len(predicted) + len(control) == len(ALL_RULES)


def test_an_unknown_rule_is_refused_rather_than_filed_as_control() -> None:
    """Defaulting would put a taint rule nobody wired up into the group
    predicted not to move, which is the group that has to stay clean for the
    placebo to mean anything."""
    import pytest

    from evals.harness.experiment import split_by_prediction

    with pytest.raises(KeyError):
        split_by_prediction([{"entry_id": "a", "rule_id": "NO-SUCH-RULE"}])


def _probed(entry_id: str, window: float | None, function: float | None) -> dict[str, object]:
    probabilities: dict[str, object] = {}
    if window is not None:
        probabilities["window"] = window
    if function is not None:
        probabilities["function"] = function
    return {"entry_id": entry_id, "rule_id": "SHELL-EXEC-UNSAFE", "probabilities": probabilities}


def test_decisiveness_is_distance_from_the_undecided_midpoint() -> None:
    """A calibrated model says "I cannot tell" by answering near one half, so
    the distance from one half is how decidable the finding was. Measuring it
    directly avoids inventing an unsure band and publishing a threshold the
    experiment would then depend on."""
    from evals.harness.experiment import decisiveness

    assert decisiveness(0.5) == 0.0
    assert decisiveness(0.95) == pytest.approx(0.45)
    assert decisiveness(0.05) == pytest.approx(0.45)


def test_a_one_sided_shift_in_decisiveness_is_reported_as_unlikely_by_chance() -> None:
    """The main effect, and the reason it needs no ground truth: if the wider
    context makes the adjudicator more decisive on the same findings, that is
    measurable without anyone knowing which findings are real."""
    from evals.harness.experiment import paired_decisiveness

    entries = [_probed(f"e{n}", window=0.52, function=0.95) for n in range(10)]

    effect = paired_decisiveness(entries)

    assert effect.n == 10
    assert effect.more_decisive == 10
    assert effect.less_decisive == 0
    assert effect.p_value < 0.01
    assert effect.median_function > effect.median_window


def test_no_movement_reports_no_evidence_rather_than_a_significant_result() -> None:
    """The expected outcome for the control group. A test that a null result
    reads as a null result, because a sign test over zero untied pairs is the
    shape most likely to produce a divide-by-zero dressed as certainty."""
    from evals.harness.experiment import paired_decisiveness

    entries = [_probed(f"e{n}", window=0.8, function=0.8) for n in range(10)]

    effect = paired_decisiveness(entries)

    assert effect.n == 10
    assert effect.more_decisive == 0 and effect.less_decisive == 0
    assert effect.p_value == 1.0


def test_an_entry_judged_under_one_condition_only_is_excluded() -> None:
    """Paired throughout: an unpaired entry would compare two different samples
    and report the difference as a context effect."""
    from evals.harness.experiment import paired_decisiveness

    entries = [
        _probed("a", window=0.52, function=0.95),
        _probed("b", window=0.52, function=None),
        _probed("c", window=None, function=0.95),
    ]

    assert paired_decisiveness(entries).n == 1


def test_the_effect_is_reported_with_its_direction_split_not_only_a_p_value() -> None:
    """A p-value with no counts hides a result driven by two entries out of a
    hundred. The counts are what a reader needs to judge whether the effect is
    worth anything."""
    from evals.harness.experiment import paired_decisiveness

    entries = [
        _probed("a", window=0.52, function=0.95),
        _probed("b", window=0.95, function=0.52),
        _probed("c", window=0.52, function=0.99),
    ]

    effect = paired_decisiveness(entries)

    assert (effect.more_decisive, effect.less_decisive, effect.tied) == (2, 1, 0)


def test_a_probability_is_recorded_under_the_condition_it_was_asked_in() -> None:
    """Two conditions write to one entry, so the condition has to be part of
    where the answer lands. Without it the second run would overwrite the first
    and the comparison would have one arm."""
    from evals.harness.experiment import record_probabilities

    entries: list[dict[str, object]] = [{"entry_id": "a", "probabilities": {"window": 0.52}}]

    updated = record_probabilities(entries, "function", {"a": 0.95})

    assert updated[0]["probabilities"] == {"window": 0.52, "function": 0.95}


def test_an_entry_the_spend_guard_skipped_records_nothing() -> None:
    """The one failure that would be invisible. A call never made must not
    become 0.0, which reads downstream as a confident "not real" and would drag
    the measured effect toward whatever the guard happened to cut off."""
    from evals.harness.experiment import record_probabilities

    entries: list[dict[str, object]] = [{"entry_id": "a", "probabilities": {}}]

    updated = record_probabilities(entries, "window", {"a": None})

    assert updated[0]["probabilities"] == {}


def test_only_entries_carrying_a_condition_s_context_are_eligible_for_it() -> None:
    """Asking for a context an entry lacks is refused by design, so the runner
    has to select before it asks rather than catch afterwards."""
    from evals.harness.experiment import eligible

    entries = [
        {"entry_id": "a", "context": "w", "flagged_offset": 0,
         "context_function": "f", "flagged_offset_function": 0},
        {"entry_id": "b", "context": "w", "flagged_offset": 0},
    ]

    assert [e["entry_id"] for e in eligible(entries, "window")] == ["a", "b"]
    assert [e["entry_id"] for e in eligible(entries, "function")] == ["a"]
