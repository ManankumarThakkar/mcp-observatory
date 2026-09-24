"""Precision, recall and F1 per rule. Runnable by anyone, against anything.

Deliberately free of project imports. `DECISIONS.md` D8 publishes this as a
script another scanner can be run against, which is only true if it needs the
benchmark file and nothing else. Two lists of records keyed by `entry_id` go
in; numbers come out.
"""

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TRUE_POSITIVE = "true_positive"
UNSURE = "unsure"


@dataclass(frozen=True)
class Score:
    """One rule's measured accuracy, and how many judgements it rests on.

    `support` is not decoration. A precision of 1.0 over four entries and over
    sixty are different claims, and publishing the first without its support
    would be exactly the kind of number this project exists not to publish.
    """

    rule_id: str
    precision: float
    recall: float
    f1: float
    support: int


def score_rule(
    predictions: Sequence[Mapping[str, Any]], labels: Sequence[Mapping[str, Any]]
) -> Score:
    """Score one rule's predictions against its labels.

    Unsure labels are dropped from both sides rather than counted against the
    arm: an entry a human could not decide from the window is evidence about
    the window, not about the model.

    Both directions of mismatch raise. A prediction for an unlabelled entry
    would shrink the denominator silently, inflating every figure computed
    from it. A label with no prediction is worse: an arm that answered only
    the entries it found easy would report a precision over the subset it
    chose, which is the most flattering number available and the least true.
    """
    by_id = {entry["entry_id"]: entry for entry in labels}
    predicted_ids = {p["entry_id"] for p in predictions}

    unknown = sorted(predicted_ids - set(by_id))
    if unknown:
        raise ValueError(f"predictions for unlabelled entries: {', '.join(unknown)}")
    unanswered = sorted(set(by_id) - predicted_ids)
    if unanswered:
        raise ValueError(f"labelled entries with no prediction: {', '.join(unanswered)}")

    scored = [
        (bool(p["verdict"]), by_id[p["entry_id"]]["label"])
        for p in predictions
        if by_id[p["entry_id"]]["label"] != UNSURE
    ]

    true_positives = sum(1 for verdict, label in scored if verdict and label == TRUE_POSITIVE)
    predicted = sum(1 for verdict, _ in scored if verdict)
    actual = sum(1 for _, label in scored if label == TRUE_POSITIVE)

    # Zero rather than a division error. An arm that predicts nothing true is
    # an arm that failed, and a traceback here would break the CI gate on
    # exactly the run that needed to report the failure.
    precision = true_positives / predicted if predicted else 0.0
    recall = true_positives / actual if actual else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    rule_id = str(next(iter(by_id.values()))["rule_id"]) if by_id else ""
    return Score(rule_id, precision, recall, f1, len(scored))


def score_all(
    predictions: Sequence[Mapping[str, Any]], labels: Sequence[Mapping[str, Any]]
) -> dict[str, Score]:
    """Score every rule separately, which is the figure the phase exists for."""
    rule_of = {entry["entry_id"]: entry["rule_id"] for entry in labels}
    by_rule: dict[str, list[Mapping[str, Any]]] = {}
    for label in labels:
        by_rule.setdefault(str(label["rule_id"]), [])

    grouped_predictions: dict[str, list[Mapping[str, Any]]] = {rule: [] for rule in by_rule}
    for prediction in predictions:
        rule = rule_of.get(prediction["entry_id"])
        if rule is None:
            raise ValueError(f"prediction for unlabelled entry: {prediction['entry_id']}")
        grouped_predictions[str(rule)].append(prediction)

    return {
        rule: score_rule(
            grouped_predictions[rule], [le for le in labels if le["rule_id"] == rule]
        )
        for rule in sorted(by_rule)
    }


def weighted_precision(
    scores: Mapping[str, Score], population: Mapping[str, int]
) -> float:
    """Corpus precision, weighting each rule by its real finding volume.

    The sample over-represents quiet rules on purpose, so the unweighted mean
    over it describes the sample and not the corpus. This is the only figure
    that may be published as "this scanner's precision"; the per-rule numbers
    are published beside it.

    A rule with no population count raises rather than weighting as zero.
    Treating it as zero silently drops it from the headline figure, which is
    the one number most likely to be quoted on its own.
    """
    missing = sorted(rule for rule in scores if rule not in population)
    if missing:
        raise ValueError(f"no corpus finding count for {', '.join(missing)}")

    total = sum(population[rule] for rule in scores)
    if not total:
        return 0.0
    return sum(score.precision * population[rule] for rule, score in scores.items()) / total


def _load(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--predictions", required=True, type=Path)
    parser.add_argument("--labels", required=True, type=Path)
    parser.add_argument("--population", type=Path, help="Rule to corpus finding count, as JSON.")
    args = parser.parse_args(argv)

    scores = score_all(_load(args.predictions), _load(args.labels))

    print(f"{'rule':24} {'precision':>10} {'recall':>8} {'f1':>6} {'n':>5}")
    for rule, score in scores.items():
        print(
            f"{rule:24} {score.precision:>10.3f} {score.recall:>8.3f} "
            f"{score.f1:>6.3f} {score.support:>5}"
        )

    if args.population:
        population = json.loads(args.population.read_text(encoding="utf-8"))
        print(f"\npopulation-weighted precision: {weighted_precision(scores, population):.3f}")
    else:
        print("\nno --population given, so no corpus figure: the per-rule numbers above", file=sys.stderr)
        print("are over a sample that over-represents quiet rules on purpose.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
