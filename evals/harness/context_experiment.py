"""Run the annotation-context experiment: the same findings judged twice."""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from analyzer.triage.base import Adjudicator, as_condition
from analyzer.triage.cache import CACHE_PATH, TriageCache, adjudicate
from analyzer.triage.jev import JevAdjudicator, post_json
from evals.golden.label import CONDITIONS
from evals.harness.experiment import (
    PairedEffect,
    eligible,
    flip_sensitivity,
    paired_decisiveness,
    per_rule_effects,
    record_probabilities,
    split_by_prediction,
)

# Every entry, under both conditions, with room for a re-run. Set from the
# corpus rather than left at the pipeline's nightly default, because the guard
# exists to stop a runaway bill and a guard that silently truncates an
# experiment is worse than no guard: the result would look complete.
DEFAULT_MAX_CALLS = 800


def run(
    path: Path,
    *,
    cache_path: Path,
    max_calls: int,
    adjudicator: Adjudicator,
) -> tuple[dict[str, PairedEffect], dict[str, PairedEffect]]:
    """Adjudicate every eligible entry under each condition, and report the effect.

    Both conditions go through the ordinary cached adjudication path, given
    entries projected onto the condition. Nothing in that path is told which
    condition it is serving, which is what makes the comparison a comparison of
    context: an arm that knew could behave differently, and the cache keys
    separate themselves because the key hashes the presented text.

    Entries are written back after each condition rather than at the end. A run
    of several hundred paid calls that lost its answers to an interrupted
    process would have to be paid for twice.

    The adjudicator is passed in rather than constructed here, so the plumbing
    can be tested without a network, a key or a prepaid balance. That is not
    only convenience: the failure worth testing for is the runner showing both
    conditions the same window, which costs real money to discover live and is
    invisible in the result - it would simply report that context makes no
    difference.
    """
    entries: list[dict[str, Any]] = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    cache = TriageCache(cache_path)

    for condition in CONDITIONS:
        pool = eligible(entries, condition)
        print(
            f"{condition}: {len(pool)} of {len(entries)} entries carry this context",
            file=sys.stderr,
        )
        result = adjudicate(
            [as_condition(entry, condition) for entry in pool],
            adjudicator=adjudicator,
            cache=cache,
            max_calls=max_calls,
        )
        answered = {
            entry_id: (None if decision is None else decision.probability)
            for entry_id, decision in result.decisions.items()
        }
        print(
            f"  {result.calls} calls, ${result.cost_usd:.4f}",
            file=sys.stderr,
        )
        # Never silent, and never with the wrong reason. A failed call and a call
        # the budget stopped short of both arrive as a missing answer, and one is
        # re-run while the other needs the cap raised.
        if result.failures:
            print(
                f"  {len(result.failures)} entries failed and can be re-run; "
                f"first: {next(iter(result.failures.values()))[:120]}",
                file=sys.stderr,
            )
        capped = sum(
            1
            for entry_id, value in answered.items()
            if value is None and entry_id not in result.failures
        )
        if capped:
            print(
                f"  {capped} entries unanswered: the spend guard stopped at "
                f"{max_calls} calls, so this condition is incomplete",
                file=sys.stderr,
            )
        entries = record_probabilities(entries, condition, answered)
        _write(path, entries)

    predicted, control = split_by_prediction(entries)
    return (
        {"predicted": paired_decisiveness(predicted)},
        {"control": paired_decisiveness(control)},
    )


def _write(path: Path, entries: Sequence[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in entries),
        encoding="utf-8",
    )


def _report(label: str, effect: PairedEffect) -> None:
    print(f"\n{label}  (n={effect.n} paired)")
    print(f"  median decisiveness, window   {effect.median_window:.3f}")
    print(f"  median decisiveness, function {effect.median_function:.3f}")
    print(
        f"  moved: {effect.more_decisive} more decisive, "
        f"{effect.less_decisive} less, {effect.tied} unchanged"
    )
    print(f"  sign test p = {effect.p_value:.4f}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument("--path", type=Path, default=Path(".cache/golden-entries.jsonl"))
    parser.add_argument("--cache", type=Path, default=CACHE_PATH)
    parser.add_argument("--max-calls", type=int, default=DEFAULT_MAX_CALLS)
    args = parser.parse_args(argv)
    if not args.path.exists():
        raise FileNotFoundError(f"no entries at {args.path}; draw the golden set first")

    predicted, control = run(
        args.path,
        cache_path=args.cache,
        max_calls=args.max_calls,
        adjudicator=JevAdjudicator(post_json),
    )
    _report("Predicted to move (taint rules)", predicted["predicted"])
    _report("Control, predicted not to move", control["control"])
    print(
        "\nThe control group is the placebo: if it moves as much as the "
        "predicted group, the effect is more text rather than the right text.",
    )

    entries = [
        json.loads(line)
        for line in args.path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    # Reported per rule because the combined figure can hide a disagreement
    # between two rules the same mechanism was claimed for, and an average is
    # where a single rule carrying the whole result becomes invisible.
    print("\nPer rule, so one rule cannot carry the others:")
    for rule_id, effect in per_rule_effects(entries).items():
        if effect.n == 0:
            continue
        print(
            f"  {rule_id:24} n={effect.n:3}  more decisive {effect.more_decisive:3}"
            f"  less {effect.less_decisive:3}  p = {effect.p_value:.4f}"
        )
    print(
        f"  Examining {len(per_rule_effects(entries))} rules, so a single rule's "
        "p-value needs a multiple-comparison correction before it means anything."
    )

    # A moved probability is not yet a consequence; one that crosses the
    # threshold changes the verdict a benchmark publishes for that finding.
    print("\nFindings whose verdict depends on which context was shown:")
    for threshold, flips in flip_sensitivity(entries).items():
        share = "n/a" if flips.share is None else f"{flips.share:.1%}"
        print(
            f"  threshold {threshold:.2f}  {flips.count:3}/{flips.n} = {share:>6}"
            f"  across {flips.servers} servers, largest contributes {flips.largest_server}"
        )
    print(
        "  A share that holds across the range is not an artefact of one "
        "threshold. Concentration is printed because a share drawn mostly from "
        "one repository is a fact about that repository."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
