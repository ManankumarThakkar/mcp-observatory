"""Ask the judge the same questions twice, and measure how often it disagrees with itself.

A context effect is only interpretable against this noise floor. If the judge
changes its verdict on identical input as often as it does when the context
changes, the "context effect" is randomness, and every flip rate this project
reports would mean nothing. Measured on 2026-09-30: 1.7% of window verdicts and
1.1% of function verdicts changed on identical input, against 18.6% when only
the context changed, and 30 of the 33 context flips recurred in the second run.
"""

import argparse
import json
import statistics
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evals.golden.label import CONDITIONS
from evals.harness.experiment import verdict


@dataclass(frozen=True)
class Stability:
    """One condition's agreement with itself across two runs."""

    condition: str
    n: int
    verdict_changes: int
    identical: int
    median_shift: float
    max_shift: float

    @property
    def share(self) -> float:
        return self.verdict_changes / self.n


@dataclass(frozen=True)
class FlipOverlap:
    """Whether the same findings change with context in both runs."""

    both: int
    only_first: int
    only_second: int

    @property
    def jaccard(self) -> float:
        union = self.both + self.only_first + self.only_second
        return self.both / union if union else 1.0


def _by_id(entries: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    return {str(entry["entry_id"]): entry for entry in entries}


def _probability(entry: Mapping[str, Any], condition: str) -> float | None:
    value = (entry.get("probabilities") or {}).get(condition)
    return float(value) if isinstance(value, int | float) else None


def retest_stability(
    first: Sequence[Mapping[str, Any]], second: Sequence[Mapping[str, Any]]
) -> dict[str, Stability]:
    """Per condition, how often two runs over identical input reach different verdicts.

    Paired by entry: an answer with no counterpart in the other run is excluded,
    because it says nothing about stability. A condition with no pairs at all is
    absent from the result rather than reported as zero changes out of zero, which
    would read as perfect stability measured on nothing.
    """
    a, b = _by_id(first), _by_id(second)
    result: dict[str, Stability] = {}
    for condition in CONDITIONS:
        pairs = [
            (pa, pb)
            for entry_id in a.keys() & b.keys()
            if (pa := _probability(a[entry_id], condition)) is not None
            and (pb := _probability(b[entry_id], condition)) is not None
        ]
        if not pairs:
            continue
        shifts = [abs(pa - pb) for pa, pb in pairs]
        result[condition] = Stability(
            condition=condition,
            n=len(pairs),
            verdict_changes=sum(1 for pa, pb in pairs if verdict(pa) != verdict(pb)),
            identical=sum(1 for shift in shifts if shift == 0.0),
            median_shift=statistics.median(shifts),
            max_shift=max(shifts),
        )
    return result


def _context_flips(entries: Mapping[str, Mapping[str, Any]]) -> set[str]:
    flipped = set()
    for entry_id, entry in entries.items():
        window, function = _probability(entry, "window"), _probability(entry, "function")
        if window is not None and function is not None and verdict(window) != verdict(function):
            flipped.add(entry_id)
    return flipped


def flip_overlap(
    first: Sequence[Mapping[str, Any]], second: Sequence[Mapping[str, Any]]
) -> FlipOverlap:
    """Which findings change with context in each run.

    The same flip rate in two runs could come from different findings each time,
    which is what noise looks like. The same findings flipping both times is what a
    property of those findings looks like.
    """
    a, b = _context_flips(_by_id(first)), _context_flips(_by_id(second))
    return FlipOverlap(both=len(a & b), only_first=len(a - b), only_second=len(b - a))


def _load(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("first", type=Path, help="Entries from the first run.")
    parser.add_argument("second", type=Path, help="Entries from the second run, same questions.")
    args = parser.parse_args(argv)

    first, second = _load(args.first), _load(args.second)
    for stability in retest_stability(first, second).values():
        print(
            f"{stability.condition:9} {stability.verdict_changes}/{stability.n} verdicts differ on "
            f"identical input ({stability.share:.1%}); identical probability "
            f"{stability.identical}/{stability.n}; median shift {stability.median_shift:.3f}, "
            f"max {stability.max_shift:.3f}"
        )
    overlap = flip_overlap(first, second)
    print(
        f"context flips in both runs {overlap.both}, only the first {overlap.only_first}, "
        f"only the second {overlap.only_second}; overlap {overlap.jaccard:.2f}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
