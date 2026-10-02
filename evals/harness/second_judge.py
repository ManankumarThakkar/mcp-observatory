"""A second judge on the frozen study, reported as exploratory.

The registered study has one judge, so whatever a second one shows cannot
confirm anything: it says whether the context effect is a property of one
model or of judging from a narrow window in general. Its answers are written
beside the snapshot, never into it, because the snapshot's stored answers are
fingerprinted and the analysis refuses one that changed.

Run in two steps, with a person deciding in between: `--sample N` measures
what a call costs on real findings, and a full run needs `--max-cost` and is
refused if that measurement projects past it.
"""

import argparse
import json
import re
import statistics
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from analyzer.sampling import draw
from analyzer.triage.base import Adjudicator, as_condition
from analyzer.triage.cache import TriageCache, adjudicate
from evals.golden.label import CONDITIONS
from evals.golden.study import STUDY_SEED, check_frozen, probability_digest
from evals.harness.analysis import flip_estimate
from evals.harness.arms import ARMS, adjudicator_for
from evals.harness.experiment import eligible, verdict
from evals.harness.stats import cohens_kappa, sign_test

Entry = Mapping[str, Any]


@dataclass
class Judged:
    answers: dict[str, dict[str, float]] = field(default_factory=dict)
    cost_usd: float = 0.0
    calls: int = 0
    stopped_at_cap: bool = False
    # "<entry_id>:<condition>" to the reason, so a refusal (which repeats) can be
    # told from a dropped connection (which does not).
    failures: dict[str, str] = field(default_factory=dict)


def paired(entries: Sequence[Entry]) -> list[Entry]:
    """Entries that carry both views, which is what a flip is measured on."""
    function = {str(e["entry_id"]) for e in eligible(entries, "function")}
    return [e for e in entries if str(e["entry_id"]) in function]


def sample_ids(entries: Sequence[Entry], size: int) -> list[str]:
    """A reproducible sample of paired findings, by the project's hashed draw."""
    chosen = draw(paired(entries), size, seed=STUDY_SEED, key=lambda e: (str(e["entry_id"]),))
    return [str(e["entry_id"]) for e in chosen]


def judge(
    entries: Sequence[Entry], *, adjudicator: Adjudicator, cache_path: Path, max_cost: float
) -> Judged:
    """Ask the judge about both views of each entry, stopping at the spend cap.

    Through the ordinary cached path, so an answer already paid for is never
    bought twice, and the two views key apart because the key hashes the text.
    The cap is checked before each call, so the last call can take spend just
    past it, by at most one call's cost.
    """
    cache = TriageCache(cache_path)
    judged = Judged()
    for entry in entries:
        answer: dict[str, float] = {}
        for condition in CONDITIONS:
            if judged.cost_usd >= max_cost:
                judged.stopped_at_cap = True
                return judged
            run = adjudicate(
                [as_condition(entry, condition)], adjudicator=adjudicator, cache=cache, max_calls=1
            )
            judged.cost_usd += run.cost_usd
            judged.calls += run.calls
            for entry_id, reason in run.failures.items():
                judged.failures[f"{entry_id}:{condition}"] = reason
            decision = run.decisions.get(str(entry["entry_id"]))
            if decision is not None:
                answer[condition] = decision.probability
        if len(answer) == len(CONDITIONS):
            judged.answers[str(entry["entry_id"])] = answer
    return judged


def failure_lines(failures: Mapping[str, str]) -> list[str]:
    """Failed calls counted by reason, with finding ids masked so reasons group."""
    if not failures:
        return []
    reasons = Counter(re.sub(r"g-\d+", "<entry>", reason)[:160] for reason in failures.values())
    return [f"{len(failures)} calls failed and can be re-run:"] + [
        f"  {count} x {reason}" for reason, count in reasons.most_common()
    ]


def shift_line(label: str, pairs: Sequence[tuple[float, float]]) -> str:
    """How a judge's probability moves from the window to the whole function.

    Needs no threshold, so it still measures context sensitivity for a judge
    whose scores all sit on one side of the midpoint, where flips cannot occur.
    """
    shifts = sorted(function - window for window, function in pairs)
    lower = sum(1 for d in shifts if d < 0)
    higher = sum(1 for d in shifts if d > 0)
    median = statistics.median(shifts)
    return (
        f"  {label} {lower} lower with the whole function, {higher} higher, "
        f"{len(shifts) - lower - higher} unchanged; sign test p = {sign_test(lower, higher):.4f}; "
        f"median shift {median:+.2f}"
    )


def summary_lines(
    entries: Sequence[Entry], answers: Mapping[str, Mapping[str, float]], *, arm: str, seed: int
) -> list[str]:
    """The arm's flip rate and its agreement with the first judge. Exploratory only."""
    answered = [e for e in entries if str(e["entry_id"]) in answers]
    rows = [
        (
            str(e["server_id"]),
            verdict(answers[str(e["entry_id"])]["window"])
            != verdict(answers[str(e["entry_id"])]["function"]),
        )
        for e in answered
    ]
    lines = [f"EXPLORATORY (not in the registration): second judge `{arm}`"]
    if not rows:
        return [*lines, "no paired findings answered"]
    lines.append(f"  verdict changes with the context on {flip_estimate(rows, seed=seed)}")
    for condition in CONDITIONS:
        first = [verdict(float(e["probabilities"][condition])) for e in answered]
        second = [verdict(answers[str(e["entry_id"])][condition]) for e in answered]
        agree = sum(a == b for a, b in zip(first, second, strict=True))
        try:
            kappa = f"kappa {cohens_kappa(first, second):.2f}"
        except ValueError:
            kappa = "kappa undefined"
        lines.append(
            f"  {condition}: {agree}/{len(answered)} verdicts agree with the first judge, {kappa}"
        )
    # Added after the 20-finding sample showed this judge scoring every finding
    # below 0.5, where the midpoint flip above cannot occur. Exploratory like
    # the rest, and labelled as added after looking.
    lines.append("  threshold-free, added after the sample (probability from window to function):")
    lines.append(
        shift_line(
            "this judge:",
            [(answers[str(e["entry_id"])]["window"], answers[str(e["entry_id"])]["function"]) for e in answered],
        )
    )
    lines.append(
        shift_line(
            "first judge, same findings:",
            [(float(e["probabilities"]["window"]), float(e["probabilities"]["function"])) for e in answered],
        )
    )
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a second judge on the frozen study.")
    parser.add_argument("--arm", required=True, choices=ARMS)
    parser.add_argument("--snapshot", type=Path, default=Path(".cache/study/snapshot.jsonl"))
    parser.add_argument("--manifest", type=Path, default=Path(".cache/study/manifest.json"))
    parser.add_argument("--out", type=Path, default=Path(".cache/study/arms"))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--sample", type=int, help="Judge this many findings to measure the cost.")
    mode.add_argument("--max-cost", type=float, help="Run in full, stopping at this many dollars.")
    args = parser.parse_args(argv)

    entries: list[dict[str, Any]] = [
        json.loads(line)
        for line in args.snapshot.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    check_frozen(entries, args.manifest)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if probability_digest(entries) != manifest["probability_digest"]:
        raise RuntimeError("the judges' stored answers changed after freezing")

    args.out.mkdir(parents=True, exist_ok=True)
    measured = args.out / f"{args.arm}.sample.json"
    pool = paired(entries)
    cache_path = args.out / f"{args.arm}.cache.jsonl"

    if args.sample is not None:
        chosen = set(sample_ids(entries, args.sample))
        judged = judge(
            [e for e in pool if str(e["entry_id"]) in chosen],
            adjudicator=adjudicator_for(args.arm),
            cache_path=cache_path,
            max_cost=float("inf"),
        )
        measured.write_text(json.dumps({"calls": judged.calls, "cost_usd": judged.cost_usd}) + "\n")
        for line in failure_lines(judged.failures):
            print(line)
        per_call = judged.cost_usd / judged.calls if judged.calls else 0.0
        print(
            f"sample: {judged.calls} calls, ${judged.cost_usd:.4f}; full run of "
            f"{2 * len(pool)} calls projects to about ${per_call * 2 * len(pool):.2f}"
        )
        return 0

    if not measured.exists():
        raise RuntimeError(f"measure a sample first: no {measured}")
    sample = json.loads(measured.read_text(encoding="utf-8"))
    per_call = sample["cost_usd"] / sample["calls"] if sample["calls"] else 0.0
    projected = per_call * 2 * len(pool)
    if projected > args.max_cost:
        raise RuntimeError(
            f"the full run is projected at ${projected:.2f}, above the cap of ${args.max_cost:.2f}"
        )
    judged = judge(pool, adjudicator=adjudicator_for(args.arm), cache_path=cache_path, max_cost=args.max_cost)
    (args.out / f"{args.arm}.jsonl").write_text(
        "".join(
            json.dumps({"entry_id": entry_id, **answer}, sort_keys=True) + "\n"
            for entry_id, answer in sorted(judged.answers.items())
        )
    )
    print(f"{judged.calls} calls, ${judged.cost_usd:.4f}" + (" (stopped at the cap)" if judged.stopped_at_cap else ""))
    for line in failure_lines(judged.failures):
        print(line)
    for line in summary_lines(entries, judged.answers, arm=args.arm, seed=STUDY_SEED):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
