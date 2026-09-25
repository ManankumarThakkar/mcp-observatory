"""The context-condition comparison, computed from the labels rather than read.

One question: does the context a labeller is shown change the precision a
benchmark reports for the same findings? The two conditions are a fixed line
window either side of the flagged line, and the enclosing function. The same
findings are judged under both, so a difference is attributable to the condition
and not to the sample.

The result that matters is not the precision gap on its own. A gap could mean
the wider context revealed false positives just as easily as true ones. What
makes the direction knowable is which entries moved: a context too narrow to
settle a taint question hides the path from origin to sink, and a hidden path
can only mean an unproven true positive, never a disproven one. So the
entries that become decidable under the wider context are counted separately,
and their composition is the finding.
"""

import math
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from analyzer.rules import ALL_RULES
from evals.golden.label import CONDITIONS

# The two labels that count as a decision. Anything else is the labeller saying
# the context did not let them answer, which is the measurement here rather than
# a gap in it.
_DECIDED = ("true_positive", "false_positive")


@dataclass(frozen=True)
class ConditionResult:
    """What one context condition reported, with the sample it reported it on.

    `n` and `decided` are both carried because they answer different questions:
    `n` is how many findings were judged, `decided` is how many could be. A
    precision quoted without both is the figure this project refuses to publish.
    """

    condition: str
    n: int
    decided: int
    unsure: int
    true_positives: int

    @property
    def precision(self) -> float | None:
        """Precision over the entries that could be decided, or None.

        None rather than zero when nothing was decided. Zero would state a
        measurement that was never made, and a condition under which every
        entry is undecidable is exactly the case worth not misreporting.
        """
        if self.decided == 0:
            return None
        return self.true_positives / self.decided


@dataclass(frozen=True)
class ContextEffect:
    """The entries a wider context made decidable, and what they turned out to be."""

    resolved: int
    true_positives: int

    @property
    def share_true(self) -> float | None:
        """The fraction of newly-decidable entries that were real.

        Compare this against the precision the narrow condition reported. If it
        is higher, the narrow window was concealing true positives, so the
        precision measured under it understates the rule.
        """
        if self.resolved == 0:
            return None
        return self.true_positives / self.resolved


def _paired(entries: list[dict[str, object]]) -> list[dict[str, str]]:
    """The label under each condition, for entries judged under both.

    Entries judged under only one condition are dropped. Keeping them would
    compare two different samples and report the difference as a condition
    effect, which is the one error this design exists to rule out.
    """
    paired = []
    for entry in entries:
        observations = entry.get("observations") or {}
        if not isinstance(observations, dict):
            continue
        labels = {}
        for condition in CONDITIONS:
            seen = observations.get(condition)
            if isinstance(seen, dict) and isinstance(seen.get("label"), str):
                labels[condition] = seen["label"]
        if len(labels) == len(CONDITIONS):
            paired.append(labels)
    return paired


def compare_conditions(
    entries: list[dict[str, object]],
) -> tuple[ConditionResult, ConditionResult]:
    """What each condition reported over the entries judged under both."""
    paired = _paired(entries)
    return tuple(  # type: ignore[return-value]
        ConditionResult(
            condition=condition,
            n=len(paired),
            decided=sum(1 for row in paired if row[condition] in _DECIDED),
            unsure=sum(1 for row in paired if row[condition] not in _DECIDED),
            true_positives=sum(
                1 for row in paired if row[condition] == "true_positive"
            ),
        )
        for condition in CONDITIONS
    )


def resolved_by_context(entries: list[dict[str, object]]) -> ContextEffect:
    """The entries the narrow condition could not settle and the wider one could."""
    narrow, wide = CONDITIONS
    moved = [
        row for row in _paired(entries)
        if row[narrow] not in _DECIDED and row[wide] in _DECIDED
    ]
    return ContextEffect(
        resolved=len(moved),
        true_positives=sum(1 for row in moved if row[wide] == "true_positive"),
    )


# A genuine handler can be shorter than a window centred on the same line - a
# three-line tool callback often is. Two orders of magnitude shorter is a
# different thing: it is a fragment of the flagged line rather than the scope
# around it. Set from the failure that prompted it, where a ten-character
# `() => null` stood in for a function of several hundred.
SUSPECT_RATIO = 0.05


def suspect_functions(
    entries: list[dict[str, object]],
) -> list[tuple[str, float]]:
    """Entries whose captured function is too small to be the enclosing scope.

    A standing check rather than a one-off inspection. Because a finding carries
    a line but no column, any function node touching that line is a candidate,
    and the first capture built for this experiment duly returned an inline
    `.catch(() => null)` as one finding's enclosing function. It was caught by
    looking at the size distribution by hand, which is not a method. This
    computes the same signal on every capture, so the failure announces itself
    instead of arriving as an unexplained cluster of undecidable entries.

    Ordered smallest first, because the smallest is the one worth reading.
    """
    suspect = []
    for entry in entries:
        window, function = entry.get("context"), entry.get("context_function")
        if not isinstance(window, str) or not isinstance(function, str):
            continue
        if not window:
            continue
        ratio = len(function) / len(window)
        if ratio < SUSPECT_RATIO:
            suspect.append((str(entry.get("entry_id")), ratio))
    return sorted(suspect, key=lambda pair: pair[1])


# Read from the rules rather than listed here, so widening a rule's prediction
# widens the analysis with no second edit, and the two cannot disagree once the
# numbers are visible.
_PREDICTED = {rule.rule_id: rule.needs_enclosing_function for rule in ALL_RULES}


def split_by_prediction(
    entries: Sequence[Mapping[str, Any]],
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    """Entries the wider context is predicted to help, and the control group.

    The control group is what lets this experiment answer its own strongest
    objection. If an adjudicator grows more confident whenever it is shown more
    text, the effect says nothing about context being the right context. A set of
    findings predicted not to move separates those two explanations: a rule
    decided by the object a value is declared in does not need the path that
    reaches it, so the enclosing function should add nothing.

    The prediction is read off the rules, which recorded it before this
    experiment existed and for unrelated reasons. That ordering matters more than
    it looks: a hypothesis registered independently of the data cannot have been
    chosen to fit it.

    An unknown rule raises rather than defaulting. Defaulting would file a taint
    rule nobody wired up into the group that must stay clean for the placebo to
    mean anything, and the experiment would report a weaker effect for a reason
    nobody could see.
    """
    predicted: list[Mapping[str, Any]] = []
    control: list[Mapping[str, Any]] = []
    for entry in entries:
        rule_id = str(entry["rule_id"])
        if rule_id not in _PREDICTED:
            raise KeyError(f"no rule declares {rule_id}, so its prediction is unknown")
        (predicted if _PREDICTED[rule_id] else control).append(entry)
    return predicted, control


# The point a calibrated answer carries no information. A model that cannot tell
# from what it was shown answers here, which is what makes distance from it a
# measure of how decidable the finding was.
UNDECIDED = 0.5


def decisiveness(probability: float) -> float:
    """How far a calibrated answer is from carrying no information.

    Used instead of an unsure band, and deliberately. Discretising a probability
    into real, not real and unsure needs two thresholds, and the experiment's
    result would then depend on where they were put - a reader could move them
    and move the finding. Distance from one half needs no threshold, uses the
    whole range, and is the quantity a calibrated model is actually reporting.
    """
    return abs(probability - UNDECIDED)


@dataclass(frozen=True)
class PairedEffect:
    """A within-entry comparison of decisiveness under the two conditions.

    The counts are reported beside the p-value because a p-value alone hides
    whether an effect rests on two entries or on ninety. The medians are reported
    because a direction with no magnitude cannot be argued about.
    """

    n: int
    median_window: float
    median_function: float
    more_decisive: int
    less_decisive: int
    tied: int
    p_value: float


def paired_decisiveness(entries: Sequence[Mapping[str, Any]]) -> PairedEffect:
    """Whether the enclosing function makes the adjudicator more decisive.

    The main effect, and the reason the experiment is affordable: it needs no
    ground truth. Whether a wider context lets a judge answer at all is a
    different question from whether the answer is right, and only the second
    needs labels. So this runs over every paired entry, and hand labelling is
    spent only on establishing which way the bias points.

    Paired per entry, so the same findings are compared under both conditions
    and a difference cannot be a difference of sample.

    A sign test rather than a t-test: decisiveness is bounded at zero and one
    half and is nowhere near normal, and the question asked here is only which
    direction entries moved. It is exact, needs no distributional assumption,
    and needs no dependency beyond the standard library.
    """
    pairs = []
    for entry in entries:
        probabilities = entry.get("probabilities") or {}
        if not isinstance(probabilities, Mapping):
            continue
        window, function = probabilities.get("window"), probabilities.get("function")
        if not isinstance(window, int | float) or not isinstance(function, int | float):
            continue
        pairs.append((decisiveness(float(window)), decisiveness(float(function))))

    more = sum(1 for before, after in pairs if after > before)
    less = sum(1 for before, after in pairs if after < before)
    return PairedEffect(
        n=len(pairs),
        median_window=statistics.median([before for before, _ in pairs]) if pairs else 0.0,
        median_function=statistics.median([after for _, after in pairs]) if pairs else 0.0,
        more_decisive=more,
        less_decisive=less,
        tied=len(pairs) - more - less,
        p_value=_sign_test(more, less),
    )


def _sign_test(more: int, less: int) -> float:
    """Two-sided exact sign test over the entries that moved.

    Ties carry no directional information and are excluded, which is the
    standard treatment. With nothing untied the answer is 1.0: no evidence,
    rather than the divide-by-zero certainty this shape invites.
    """
    untied = more + less
    if untied == 0:
        return 1.0
    smaller = min(more, less)
    ways = sum(math.comb(untied, i) for i in range(smaller + 1))
    tail = ways / float(2**untied)
    return min(1.0, 2.0 * tail)
