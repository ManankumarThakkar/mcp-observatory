"""Statistics the study needs, in the standard library only."""

import math
import random
from collections.abc import Callable, Hashable, Sequence
from dataclasses import dataclass
from statistics import NormalDist
from typing import TypeVar

T = TypeVar("T")


def sign_test(more: int, less: int) -> float:
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


def sign_test_sample_size(p_alt: float, *, alpha: float = 0.05, power: float = 0.8) -> int:
    """Untied pairs a two-sided sign test needs to detect `p_alt` against one half.

    Normal approximation to the binomial, which is standard for sizing and is
    conservative enough at the sizes this study reaches. Used before any person
    labels anything, so the sample size is fixed in advance: sizing it after
    looking at results is optional stopping, and it inflates false positives.
    """
    if not 0.5 < p_alt < 1.0:
        raise ValueError(f"p_alt must lie strictly between 0.5 and 1, got {p_alt}")
    z_alpha = NormalDist().inv_cdf(1 - alpha / 2)
    z_power = NormalDist().inv_cdf(power)
    spread = math.sqrt(p_alt * (1 - p_alt))
    return math.ceil(((z_alpha * 0.5 + z_power * spread) / (p_alt - 0.5)) ** 2)


def cluster_bootstrap_ci(
    rows: Sequence[T],
    *,
    cluster: Callable[[T], Hashable],
    statistic: Callable[[Sequence[T]], float],
    seed: int,
    n_boot: int = 2000,
    level: float = 0.95,
) -> tuple[float, float]:
    """Percentile interval from resampling whole clusters, never single rows.

    Findings are not independent: one function produced three entries in the
    disagreement set and one server contributed six. Resampling rows would treat
    each as fresh evidence and report an interval far narrower than the data
    supports. Resampling servers keeps every server's findings together.

    Seeded `random.Random` rather than the project's hashed draw, because this is
    a Monte Carlo estimate reported with its seed and resample count, not a
    published sample whose membership a reader must reproduce.
    """
    groups: dict[Hashable, list[T]] = {}
    for row in rows:
        groups.setdefault(cluster(row), []).append(row)
    keys = sorted(groups, key=repr)
    if not keys:
        raise ValueError("no rows to resample")
    rng = random.Random(seed)
    estimates = sorted(
        statistic([row for key in rng.choices(keys, k=len(keys)) for row in groups[key]])
        for _ in range(n_boot)
    )
    low = math.floor((1 - level) / 2 * n_boot)
    high = min(math.ceil((1 + level) / 2 * n_boot) - 1, n_boot - 1)
    return estimates[low], estimates[high]


def cohens_kappa(first: Sequence[str], second: Sequence[str]) -> float:
    """Agreement between two annotators beyond what chance alone produces.

    Raises when both annotators used a single category, where kappa is
    undefined. Returning 1.0 there would report perfect agreement on a set that
    measured nothing; the caller reports raw agreement instead.
    """
    if len(first) != len(second):
        raise ValueError("both annotators must label the same items")
    if not first:
        raise ValueError("no items to compare")
    n = len(first)
    observed = sum(a == b for a, b in zip(first, second, strict=True)) / n
    expected = sum(
        (first.count(c) / n) * (second.count(c) / n) for c in set(first) | set(second)
    )
    if math.isclose(expected, 1.0):
        raise ValueError("kappa is undefined when both annotators used one category")
    return (observed - expected) / (1 - expected)


def brier_score(probabilities: Sequence[float], outcomes: Sequence[bool]) -> float:
    """Mean squared distance between a probability and what happened."""
    if len(probabilities) != len(outcomes) or not probabilities:
        raise ValueError("need one outcome per probability, and at least one")
    return sum((p - float(o)) ** 2 for p, o in zip(probabilities, outcomes, strict=True)) / len(
        probabilities
    )


@dataclass(frozen=True)
class CalibrationBin:
    lower: float
    upper: float
    n: int
    mean_predicted: float
    observed_rate: float


def reliability(
    probabilities: Sequence[float], outcomes: Sequence[bool], *, bins: int = 5
) -> list[CalibrationBin]:
    """Equal-width bins of predicted probability against the observed rate.

    Empty bins are omitted rather than reported as zero, which would read as a
    measured rate of nothing.
    """
    if len(probabilities) != len(outcomes):
        raise ValueError("need one outcome per probability")
    grouped: dict[int, list[tuple[float, bool]]] = {}
    for p, o in zip(probabilities, outcomes, strict=True):
        grouped.setdefault(min(int(p * bins), bins - 1), []).append((p, o))
    return [
        CalibrationBin(
            lower=index / bins,
            upper=(index + 1) / bins,
            n=len(members),
            mean_predicted=sum(p for p, _ in members) / len(members),
            observed_rate=sum(1 for _, o in members if o) / len(members),
        )
        for index, members in sorted(grouped.items())
    ]


def expected_calibration_error(table: Sequence[CalibrationBin]) -> float:
    """Gap between predicted and observed rates, weighted by each bin's size."""
    total = sum(b.n for b in table)
    if not total:
        raise ValueError("no predictions to assess")
    return sum(b.n / total * abs(b.mean_predicted - b.observed_rate) for b in table)
