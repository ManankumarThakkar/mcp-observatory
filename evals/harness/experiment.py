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
from analyzer.sampling import draw
from analyzer.triage.base import CONTEXT_FIELDS
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


def eligible(
    entries: Sequence[Mapping[str, Any]], condition: str
) -> list[Mapping[str, Any]]:
    """The entries that carry the context a condition needs.

    Selected before asking rather than caught afterwards, because projecting an
    entry onto a context it does not have raises on purpose: a silent fallback
    to the window would record two observations of one context. A rule whose
    findings sit at the top level of a file has no enclosing function, so the
    two conditions legitimately have different eligible sets, and the paired
    comparison takes the intersection by construction.
    """
    field_names = CONTEXT_FIELDS[condition]
    return [
        entry
        for entry in entries
        if all(entry.get(name) is not None for name in field_names)
    ]


def record_probabilities(
    entries: Sequence[Mapping[str, Any]],
    condition: str,
    results: Mapping[str, float | None],
) -> list[dict[str, Any]]:
    """Write one condition's answers onto the entries without disturbing the other.

    Keyed by condition because two runs write to one entry, and a flat field
    would let the second overwrite the first and leave the comparison with one
    arm.

    An entry the spend guard never asked about records nothing. That is the
    distinction worth protecting: a missing answer stored as 0.0 is
    indistinguishable downstream from a confident "not real", and it would drag
    the measured effect toward wherever the guard happened to stop.
    """
    if condition not in CONTEXT_FIELDS:
        raise ValueError(
            f"condition must be one of {', '.join(CONTEXT_FIELDS)}, got {condition!r}"
        )

    updated = []
    for entry in entries:
        fresh = dict(entry)
        probabilities = dict(fresh.get("probabilities") or {})
        answer = results.get(str(fresh["entry_id"]))
        if answer is not None:
            probabilities[condition] = answer
        fresh["probabilities"] = probabilities
        updated.append(fresh)
    return updated


def label_priority(
    entries: Sequence[Mapping[str, Any]], *, size: int, seed: int
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    """The entries worth labelling by hand, and a control sample for the base rate.

    Two groups, because the interesting number is a comparison. The share of
    context-resolved findings that turn out to be real means nothing on its own;
    it has to be read against the share among findings the narrow window already
    settled. If the first is higher, a benchmark built on the narrow window was
    concealing true positives and its precision understated the rule.

    The first group is ranked by how much the wider context moved the
    adjudicator, not cut at a threshold. A threshold would have to be chosen and
    then defended, and a reader could move it and move the finding. Ranking only
    decides where labelling effort goes; it does not enter the reported figure,
    and that distinction is worth stating whenever the number is quoted.

    The control is drawn through the project's one sampling method, so it is
    reproducible by someone not running this code and an entry's position depends
    only on its own identity. That second property is what lets the population
    grow later without discarding labels somebody spent hours making.

    Unpaired entries appear in neither. A movement cannot be computed from one
    observation, and a base rate drawn from a different population is not a base
    rate for this one.
    """
    paired = []
    for entry in entries:
        probabilities = entry.get("probabilities") or {}
        if not isinstance(probabilities, Mapping):
            continue
        window, function = probabilities.get("window"), probabilities.get("function")
        if isinstance(window, int | float) and isinstance(function, int | float):
            paired.append((entry, decisiveness(float(function)) - decisiveness(float(window))))

    moved = [entry for entry, _ in sorted(paired, key=lambda pair: -pair[1])][:size]
    control = draw(
        [entry for entry, _ in paired],
        size,
        seed=seed,
        key=lambda entry: (str(entry["entry_id"]),),
    )
    return moved, control


# Reported across a range rather than at one point. A single threshold invites
# the suspicion that it was chosen to suit the answer, and showing the
# sensitivity is cheaper than defending a choice.
FLIP_THRESHOLDS = (0.4, 0.5, 0.6, 0.7)


@dataclass(frozen=True)
class FlipResult:
    """Findings a benchmark would classify differently under the two contexts.

    Concentration travels with the count on purpose. A share drawn mostly from
    one repository is a fact about that repository, and this project has already
    had to publish that caveat once, about a pilot where 22 of 43 findings came
    from a single server.
    """

    threshold: float
    count: int
    n: int
    by_rule: dict[str, int]
    servers: int
    largest_server: int

    @property
    def share(self) -> float | None:
        return self.count / self.n if self.n else None


def _paired_probabilities(
    entries: Sequence[Mapping[str, Any]],
) -> list[tuple[Mapping[str, Any], float, float]]:
    """Entries carrying an answer under both conditions, with those answers."""
    rows = []
    for entry in entries:
        probabilities = entry.get("probabilities") or {}
        if not isinstance(probabilities, Mapping):
            continue
        window, function = probabilities.get("window"), probabilities.get("function")
        if isinstance(window, int | float) and isinstance(function, int | float):
            rows.append((entry, float(window), float(function)))
    return rows


def verdict_flips(
    entries: Sequence[Mapping[str, Any]], *, threshold: float
) -> FlipResult:
    """Findings whose side of the threshold depends on which context was shown.

    This is the consequence a moved probability does not yet have. A benchmark
    publishes a classification, so a probability that shifts within one side
    changes nothing anybody reads, while one that crosses over changes the
    published verdict for that finding - from an annotation choice no benchmark
    documents.

    Counted in both directions. A flip that turns a finding from real to not real
    is exactly as much instability as the reverse, and counting only the flattering
    direction is how a variance result gets reported as a bias result.
    """
    flipped = [
        (entry, window, function)
        for entry, window, function in _paired_probabilities(entries)
        if (window >= threshold) != (function >= threshold)
    ]
    by_rule: dict[str, int] = {}
    for entry, _, _ in flipped:
        rule_id = str(entry["rule_id"])
        by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
    servers = [str(entry.get("server_id", "")) for entry, _, _ in flipped]
    counts = {server: servers.count(server) for server in set(servers)}
    return FlipResult(
        threshold=threshold,
        count=len(flipped),
        n=len(_paired_probabilities(entries)),
        by_rule=by_rule,
        servers=len(counts),
        largest_server=max(counts.values()) if counts else 0,
    )


def flip_sensitivity(
    entries: Sequence[Mapping[str, Any]],
    *,
    thresholds: Sequence[float] = FLIP_THRESHOLDS,
) -> dict[float, FlipResult]:
    """The flip share at each threshold, so a reader can see it is not an artefact."""
    return {threshold: verdict_flips(entries, threshold=threshold) for threshold in thresholds}


def per_rule_effects(entries: Sequence[Mapping[str, Any]]) -> dict[str, PairedEffect]:
    """The decisiveness effect for each rule separately.

    The combined figure hid a disagreement worth more than the average: of the two
    rules the mechanism was predicted to help, one moved and the other did not. A
    mechanism claimed for a class of rules has to be shown for the class, and an
    average over them is exactly where a single rule carrying the result becomes
    invisible.
    """
    rules = sorted({str(entry["rule_id"]) for entry in entries})
    return {
        rule_id: paired_decisiveness(
            [entry for entry in entries if str(entry["rule_id"]) == rule_id]
        )
        for rule_id in rules
    }


def verdict(probability: float) -> str:
    """The classification a calibrated probability implies.

    At the midpoint, not at a tuned threshold. One half is simply what "more
    likely than not" means for a calibrated number, so it needs no support from
    the data and cannot be accused of having been picked to suit it. Tuning a
    threshold is for trading precision against recall, and that trade needs
    ground truth this does not yet have.

    The choice is also not load-bearing: the flip share this feeds is stable
    between 16% and 22% across thresholds from 0.40 to 0.70, which is reported
    beside it so a reader can see that for themselves.
    """
    return "true_positive" if probability >= UNDECIDED else "false_positive"


def record_verdicts(entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Turn each condition's probability into a recorded observation.

    Recorded rather than recomputed on demand, so a disagreement between the two
    contexts is visible in the data to anyone reading it. Until these exist,
    `is_contested` reports nothing on real entries however far apart the contexts
    are, because it reads observations and the runner had written only
    probabilities.

    A human observation is never overwritten. Agreement between a human and a
    model is a figure this project intends to publish, and an overwrite destroys
    the thing being measured.
    """
    updated = []
    for entry in entries:
        fresh = dict(entry)
        observations = dict(fresh.get("observations") or {})
        probabilities = fresh.get("probabilities") or {}
        if isinstance(probabilities, Mapping):
            for condition, probability in probabilities.items():
                if not isinstance(probability, int | float):
                    continue
                existing = observations.get(condition)
                if isinstance(existing, Mapping) and existing.get("labelled_by") == "human":
                    continue
                observations[condition] = {
                    "label": verdict(float(probability)),
                    "reason": f"calibrated probability {probability:.2f} at the midpoint",
                    "labelled_by": "model",
                }
        if observations:
            fresh["observations"] = observations
        updated.append(fresh)
    return updated
