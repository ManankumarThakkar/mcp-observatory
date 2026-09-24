"""Sweep the threshold, and choose one by a stated policy rather than by eye."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from evals.harness.score import score_rule

# The precision a published threshold must clear. Stated rather than derived,
# because it is a policy about what this project is willing to send a
# maintainer, not a property of any model. Four in five reported findings
# being real is the bar; below it the noise costs more attention than the
# findings are worth.
PRECISION_FLOOR = 0.80


@dataclass(frozen=True)
class ThresholdPoint:
    """What one cut-off would have produced on the labelled set."""

    threshold: float
    precision: float
    recall: float
    f1: float


def sweep_thresholds(
    decisions: Mapping[str, float],
    labels: Sequence[Mapping[str, object]],
    *,
    steps: int = 101,
) -> list[ThresholdPoint]:
    """Score every cut-off from 0 to 1, so the whole curve is publishable.

    D12 publishes the threshold beside the results and the register requires
    stating what moving it would cost in either direction. That is a
    precision-recall curve, and a curve read off by eye is not reproducible.

    The comparison is `>=`, so a decision exactly equal to the threshold
    counts as positive. An off-by-one here shifts every published figure by
    whatever sits on the boundary, silently.
    """
    missing = sorted(str(entry["entry_id"]) for entry in labels if entry["entry_id"] not in decisions)
    if missing:
        raise ValueError(f"no decision for labelled entries: {', '.join(missing)}")

    points: list[ThresholdPoint] = []
    for step in range(steps):
        threshold = step / (steps - 1)
        predictions = [
            {"entry_id": entry_id, "verdict": probability >= threshold}
            for entry_id, probability in decisions.items()
        ]
        score = score_rule(predictions, labels)
        points.append(ThresholdPoint(threshold, score.precision, score.recall, score.f1))
    return points


def choose_threshold(
    points: Sequence[ThresholdPoint], *, floor: float = PRECISION_FLOOR
) -> ThresholdPoint:
    """The most recall available at or above the precision floor.

    A stated policy, not an optimum. Maximising F1 treats a false positive and
    a missed vulnerability as equally costly, which they are not for a tool
    whose output goes to a maintainer's inbox: a false positive spends someone
    else's attention, and a missed one leaves a real problem in place.

    Raises when nothing clears the floor rather than returning the best
    available. Lowering the bar to whatever the model managed would turn the
    published precision from a standard the tool met into a description of how
    the tool happened to behave.
    """
    clearing = [point for point in points if point.precision >= floor]
    if not clearing:
        best = max((point.precision for point in points), default=0.0)
        raise ValueError(
            f"no threshold reaches precision {floor}; the best available is {best:.3f}. "
            "Publish that rather than lowering the floor to fit."
        )
    # Ties toward the higher threshold: where two cut-offs buy the same
    # recall, the stricter one leaves more headroom before precision falls.
    return max(clearing, key=lambda point: (point.recall, point.threshold))
