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


def test_the_entries_that_moved_most_are_offered_for_labelling_first() -> None:
    """Claim two needs ground truth, but only where it changes the answer.

    Whether a wider context lets a judge answer is already measured without
    labels. What labels are for is the direction: if the findings a narrow window
    leaves undecided are disproportionately real, then a benchmark built on that
    window understates precision. The entries that moved are where that is
    decided, so they are where hand labelling is worth spending.
    """
    from evals.harness.experiment import label_priority

    entries = [
        _probed("small", window=0.60, function=0.65),
        _probed("large", window=0.51, function=0.98),
        _probed("middle", window=0.55, function=0.80),
    ]

    moved, _ = label_priority(entries, size=2, seed=1)

    assert [e["entry_id"] for e in moved] == ["large", "middle"]


def test_a_control_sample_is_drawn_for_the_base_rate() -> None:
    """The share of the moved entries that are real means nothing on its own. It
    has to be compared against the share among findings the window already
    settled, and that comparison needs its own sample, drawn without regard to
    how much anything moved."""
    from evals.harness.experiment import label_priority

    entries = [_probed(f"e{n}", window=0.5 + n / 100, function=0.9) for n in range(20)]

    _, control = label_priority(entries, size=5, seed=1)

    assert len(control) == 5


def test_the_control_sample_is_reproducible_and_survives_a_redraw() -> None:
    """Drawn through the project's one sampling method, so a labelled entry stays
    in the sample when the population grows. Anything else would throw away
    labels somebody spent hours making."""
    from evals.harness.experiment import label_priority

    smaller = [_probed(f"e{n}", window=0.52, function=0.9) for n in range(20)]
    larger = smaller + [_probed(f"e{n}", window=0.52, function=0.9) for n in range(20, 40)]

    _, first = label_priority(smaller, size=5, seed=7)
    _, again = label_priority(smaller, size=5, seed=7)

    assert [e["entry_id"] for e in first] == [e["entry_id"] for e in again]

    # The guarantee that matters: an entry's position depends only on its own
    # identity and the seed, so the smaller population's order survives intact
    # inside the larger one's. Without it, adding entries would reshuffle the
    # control sample and discard labels somebody spent hours making.
    _, small_order = label_priority(smaller, size=len(smaller), seed=7)
    _, large_order = label_priority(larger, size=len(larger), seed=7)
    small_ids = [e["entry_id"] for e in small_order]
    kept = [e["entry_id"] for e in large_order if e["entry_id"] in set(small_ids)]

    assert kept == small_ids


def test_an_unpaired_entry_is_offered_for_neither() -> None:
    """A decisiveness increase cannot be computed from one observation, and a
    base rate drawn from unpaired entries would not be the same population."""
    from evals.harness.experiment import label_priority

    entries = [
        _probed("paired", window=0.52, function=0.98),
        _probed("half", window=0.52, function=None),
    ]

    moved, control = label_priority(entries, size=5, seed=1)

    assert [e["entry_id"] for e in moved] == ["paired"]
    assert [e["entry_id"] for e in control] == ["paired"]


def _probed_rule(entry_id: str, rule_id: str, window: float, function: float,
                 server_id: str = "a/one") -> dict[str, object]:
    return {
        "entry_id": entry_id,
        "rule_id": rule_id,
        "server_id": server_id,
        "probabilities": {"window": window, "function": function},
    }


def test_a_verdict_flip_is_counted_when_the_context_changes_the_side() -> None:
    """The finding that survived when the pre-registered one did not.

    A probability that moves is not yet a consequence; a probability that crosses
    the decision threshold is. This counts the findings a benchmark would
    classify differently purely because of which context its annotator was shown.
    """
    from evals.harness.experiment import verdict_flips

    entries = [
        _probed_rule("flip-up", "SHELL-EXEC-UNSAFE", 0.45, 0.80),
        _probed_rule("flip-down", "SHELL-EXEC-UNSAFE", 0.80, 0.45),
        _probed_rule("moved-but-same-side", "PATH-TRAVERSAL", 0.55, 0.95),
    ]

    flips = verdict_flips(entries, threshold=0.5)

    assert flips.count == 2
    assert flips.n == 3
    assert flips.share == pytest.approx(2 / 3)
    assert flips.by_rule == {"SHELL-EXEC-UNSAFE": 2}


def test_a_flip_share_is_reported_with_its_concentration() -> None:
    """The caveat that has to travel with the number. A share drawn mostly from
    one repository is a fact about that repository, and this project has already
    had to publish that caveat once about a pilot where 22 of 43 findings came
    from a single server."""
    from evals.harness.experiment import verdict_flips

    entries = [
        _probed_rule("a", "SHELL-EXEC-UNSAFE", 0.45, 0.80, server_id="x/one"),
        _probed_rule("b", "SHELL-EXEC-UNSAFE", 0.45, 0.80, server_id="x/one"),
        _probed_rule("c", "SHELL-EXEC-UNSAFE", 0.45, 0.80, server_id="y/two"),
    ]

    flips = verdict_flips(entries, threshold=0.5)

    assert flips.servers == 2
    assert flips.largest_server == 2


def test_the_flip_share_is_reported_across_thresholds_not_at_one() -> None:
    """A single threshold invites the suspicion that it was chosen. Reporting the
    sensitivity is cheaper than defending a choice, and a share that holds across
    the range is the evidence that it is not an artefact of one."""
    from evals.harness.experiment import flip_sensitivity

    entries = [_probed_rule("a", "SHELL-EXEC-UNSAFE", 0.45, 0.80)]

    across = flip_sensitivity(entries, thresholds=(0.4, 0.5, 0.6))

    assert sorted(across) == [0.4, 0.5, 0.6]
    assert across[0.5].count == 1
    assert across[0.4].count == 0, "0.45 and 0.80 are both above 0.40"


def test_each_rule_gets_its_own_effect_so_one_cannot_carry_the_others() -> None:
    """The combined figure hid a disagreement: one taint rule moved and the other
    did not. A mechanism claimed for both rules has to be shown for both, and a
    per-rule breakdown is what makes that checkable rather than averaged away."""
    from evals.harness.experiment import per_rule_effects

    entries = [
        _probed_rule("a", "SHELL-EXEC-UNSAFE", 0.51, 0.95),
        _probed_rule("b", "SHELL-EXEC-UNSAFE", 0.51, 0.95),
        _probed_rule("c", "PATH-TRAVERSAL", 0.95, 0.51),
    ]

    effects = per_rule_effects(entries)

    assert effects["SHELL-EXEC-UNSAFE"].more_decisive == 2
    assert effects["PATH-TRAVERSAL"].less_decisive == 1
