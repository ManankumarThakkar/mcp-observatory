"""The pre-registered analysis of the annotation-context study.

Implements `docs/study/preregistration.md` and nothing else. It reads the
frozen snapshot and the people's labels, and never a judge: every probability
it uses was stored in the snapshot before registration.
"""

import argparse
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from analyzer.sampling import draw
from evals.golden.annotate import annotation_paths, merge_human_labels, read_annotations
from evals.golden.label import CONDITIONS, LABELS
from evals.golden.study import (
    CONTROL_SIZE,
    STUDY_SEED,
    annotation_sample,
    check_frozen,
    probability_digest,
)
from evals.harness.experiment import verdict
from evals.harness.stats import (
    brier_score,
    cluster_bootstrap_ci,
    cohens_kappa,
    expected_calibration_error,
    reliability,
    sign_test,
)

DECIDED = ("true_positive", "false_positive")

Entry = Mapping[str, Any]


def _paired(entry: Entry) -> tuple[float, float] | None:
    probabilities = entry.get("probabilities") or {}
    window, function = probabilities.get("window"), probabilities.get("function")
    if isinstance(window, int | float) and isinstance(function, int | float):
        return float(window), float(function)
    return None


def _human_decided(entry: Entry) -> bool:
    return entry.get("labelled_by") == "human" and entry.get("label") in DECIDED


def _server(entry: Entry) -> str:
    # Strict: a missing server would silently merge findings into one cluster.
    return str(entry["server_id"])


@dataclass(frozen=True)
class WindowError:
    entry_id: str
    server_id: str
    credulous: bool


def window_errors(entries: Sequence[Entry]) -> list[WindowError]:
    """Each disagreement the window judge got wrong against a person's label.

    Human labels only, by construction rather than by a parameter: this is the
    primary hypothesis, and it cannot be computed against a model's reading.
    """
    rows = []
    for entry in entries:
        pair = _paired(entry)
        if pair is None or not _human_decided(entry):
            continue
        said = verdict(pair[0])
        if said == verdict(pair[1]) or said == entry["label"]:
            continue
        rows.append(
            WindowError(
                entry_id=str(entry["entry_id"]),
                server_id=_server(entry),
                credulous=said == "true_positive",
            )
        )
    return rows


def credulous_share(rows: Sequence[WindowError]) -> float:
    return sum(1 for r in rows if r.credulous) / len(rows)


def credulous_share_ci(rows: Sequence[WindowError], *, seed: int) -> tuple[float, float]:
    """95% interval on the credulous share, resampling servers rather than findings."""
    return cluster_bootstrap_ci(
        rows, cluster=lambda r: r.server_id, statistic=credulous_share, seed=seed
    )


def one_per_server(rows: Sequence[WindowError], *, seed: int) -> list[WindowError]:
    """Sensitivity check: one error per server, chosen by hashed identity.

    Not the first one seen, which would let the order of a file decide the
    result. The project's hashed draw makes the choice reproducible by anyone,
    and it was fixed before any person labelled anything.
    """
    by_server: dict[str, list[WindowError]] = {}
    for row in rows:
        by_server.setdefault(row.server_id, []).append(row)
    return [
        draw(group, 1, seed=seed, key=lambda r: (r.entry_id,))[0]
        for _, group in sorted(by_server.items())
    ]


def _disagrees(entry: Entry) -> bool:
    pair = _paired(entry)
    return pair is not None and verdict(pair[0]) != verdict(pair[1])


def unsure_line(entries: Sequence[Entry]) -> str:
    """How many people answered unsure, and how many of those H1 and H3 lost."""
    unsure = [e for e in entries if e.get("labelled_by") == "human" and e.get("label") == "unsure"]
    human = sum(1 for e in entries if e.get("labelled_by") == "human")
    disputed = sum(1 for e in unsure if _disagrees(e))
    return (
        f"Unsure: {len(unsure)} of {human} human-labelled findings, {disputed} of them on a "
        "disagreement; excluded from H1 and H3."
    )


def h1_lines(entries: Sequence[Entry], *, seed: int) -> list[str]:
    """The primary hypothesis as the report prints it, with its sensitivity check."""
    rows = window_errors(entries)
    if not rows:
        return ["H1: no human-labelled window errors, so nothing to test."]
    credulous = sum(1 for r in rows if r.credulous)
    missed = len(rows) - credulous
    low, high = credulous_share_ci(rows, seed=seed)
    single = one_per_server(rows, seed=seed)
    single_credulous = sum(1 for r in single if r.credulous)
    return [
        (
            f"H1: window errors on disagreements, human labels: {credulous} credulous, "
            f"{missed} missed, sign test p = {sign_test(credulous, missed):.4f}"
        ),
        (
            f"    credulous share {credulous_share(rows):.2f}, 95% server-clustered interval "
            f"{low:.2f} to {high:.2f}"
        ),
        (
            f"    one finding per server: {single_credulous} credulous of {len(single)}, "
            f"p = {sign_test(single_credulous, len(single) - single_credulous):.4f}"
        ),
    ]


def _flip_share(rows: Sequence[tuple[str, bool]]) -> float:
    return sum(1 for _, flipped in rows if flipped) / len(rows)


def flip_estimate(rows: Sequence[tuple[str, bool]], *, seed: int) -> str:
    flipped = sum(1 for _, changed in rows if changed)
    low, high = cluster_bootstrap_ci(
        rows, cluster=lambda r: r[0], statistic=_flip_share, seed=seed
    )
    return (
        f"{flipped} of {len(rows)} paired findings ({flipped / len(rows):.1%}), "
        f"95% server-clustered interval {low:.1%} to {high:.1%}"
    )


def h2_lines(entries: Sequence[Entry], *, seed: int) -> list[str]:
    """How often the verdict changes with the context, and without the largest server.

    The largest contributor is chosen by its number of flips, ties broken by
    name, so the left-out server is fixed by the data rather than picked.
    """
    rows = [
        (_server(e), verdict(pair[0]) != verdict(pair[1]))
        for e in entries
        if (pair := _paired(e)) is not None
    ]
    if not rows:
        return ["H2: no paired findings."]
    lines = [f"H2: the verdict changes with the context on {flip_estimate(rows, seed=seed)}"]
    flips = Counter(server for server, changed in rows if changed)
    if flips:
        largest, count = min(flips.items(), key=lambda item: (-item[1], item[0]))
        rest = [row for row in rows if row[0] != largest]
        if rest:
            lines.append(
                f"    without {largest} ({count} of {flips.total()} flips): "
                f"{flip_estimate(rest, seed=seed)}"
            )
    lines.append("    compare with the test-retest noise floor stated in the registration")
    return lines


def h3_lines(entries: Sequence[Entry]) -> list[str]:
    """Which view a person sided with on each disagreement. Descriptive only.

    On a disagreement exactly one view matches a decided label, so this count
    is the whole accuracy gap between the conditions. No test is run: the
    registration fixed H3 as underpowered and exploratory.
    """
    function_right = window_right = 0
    for entry in entries:
        pair = _paired(entry)
        if pair is None or not _human_decided(entry) or verdict(pair[0]) == verdict(pair[1]):
            continue
        if verdict(pair[0]) == entry["label"]:
            window_right += 1
        else:
            function_right += 1
    decided = function_right + window_right
    if not decided:
        return ["H3 (exploratory): no human-decided disagreements."]
    return [
        (
            f"H3 (exploratory): function right {function_right}, window right {window_right}, "
            f"of {decided} decided disagreements ({function_right / decided:.0%} function). "
            "Descriptive only, no claim."
        )
    ]


def h4_lines(entries: Sequence[Entry], control: frozenset[str]) -> list[str]:
    """Calibration on the random control only, and model-versus-human agreement.

    The control alone, because the disagreement set is selected by the judges'
    own answers and would bias any calibration estimate drawn from it.
    """
    lines = []
    settled = [e for e in entries if str(e["entry_id"]) in control and _human_decided(e)]
    for condition in CONDITIONS:
        pairs = [
            (float(e["probabilities"][condition]), e["label"] == "true_positive")
            for e in settled
            if isinstance((e.get("probabilities") or {}).get(condition), int | float)
        ]
        if not pairs:
            lines.append(f"H4 {condition}: no human-labelled control findings.")
            continue
        probabilities, outcomes = [p for p, _ in pairs], [o for _, o in pairs]
        table = reliability(probabilities, outcomes)
        lines.append(
            f"H4 {condition}: n={len(pairs)}  Brier {brier_score(probabilities, outcomes):.3f}  "
            f"calibration error {expected_calibration_error(table):.3f}"
        )
        lines.extend(
            f"    {b.lower:.2f}-{b.upper:.2f}  n={b.n:<3}  predicted {b.mean_predicted:.2f}  "
            f"observed {b.observed_rate:.2f}"
            for b in table
        )
    both = [
        (str(e["model_label"]), str(e["label"]))
        for e in entries
        if e.get("labelled_by") == "human" and e.get("model_label") is not None
    ]
    if both:
        agreed = sum(1 for model, person in both if model == person)
        try:
            kappa = f"kappa {cohens_kappa([m for m, _ in both], [h for _, h in both]):.2f}"
        except ValueError:
            kappa = "kappa undefined"
        lines.append(f"H4 model vs people: {agreed}/{len(both)} agree, {kappa}")
    return lines


def study_lines(entries: Sequence[Entry], manifest: Mapping[str, Any]) -> list[str]:
    """Every pre-registered figure, in registration order, from the frozen manifest."""
    seed = int(manifest["sample_seed"])
    return [
        unsure_line(entries),
        *h1_lines(entries, seed=seed),
        *h2_lines(entries, seed=seed),
        *h3_lines(entries),
        *h4_lines(entries, frozenset(str(i) for i in manifest["control"])),
    ]


def read_adjudications(path: Path) -> dict[str, str]:
    """Each settled disagreement's label, refusing any record without a reason.

    The registration promises every conflict is adjudicated with a recorded
    reason, so a bare verdict is not accepted.
    """
    settled: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("label") not in LABELS:
            raise ValueError(f"adjudicated label must be one of {', '.join(LABELS)}")
        if not str(record.get("reason", "")).strip():
            raise ValueError(f"the adjudication of {record['entry_id']} needs a reason")
        settled[str(record["entry_id"])] = str(record["label"])
    return settled


def _check_unchanged(entries: Sequence[Entry], manifest: Mapping[str, Any]) -> None:
    """Refuse anything the registration fixed that no longer holds.

    The snapshot digest covers only what the judges were shown, so the stored
    answers, the seed and the drawn sample are each checked here as well.
    """
    if manifest["sample_seed"] != STUDY_SEED:
        raise RuntimeError(f"the manifest's seed {manifest['sample_seed']} is not the registered seed")
    if probability_digest(entries) != manifest["probability_digest"]:
        raise RuntimeError("the judges' stored answers changed after freezing")
    sample = annotation_sample(entries, control_size=CONTROL_SIZE, seed=STUDY_SEED)
    if (
        sample.queue != [str(i) for i in manifest["queue"]]
        or sorted(sample.disagreement) != sorted(manifest["disagreement"])
        or sorted(sample.control) != sorted(manifest["control"])
    ):
        raise RuntimeError("the manifest's sample does not follow from the snapshot")
    if any(e.get("labelled_by") == "human" for e in entries):
        raise RuntimeError("the frozen snapshot already carries a human label")


def load_study(
    snapshot: Path,
    manifest_path: Path,
    annotations: Mapping[str, Mapping[str, Mapping[str, Any]]],
    *,
    adjudicated: Mapping[str, str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """The frozen entries with the people's labels on them, or a refusal.

    Refuses a changed snapshot before reading any label, refuses before
    annotation is complete, and refuses unresolved disagreements, because
    dropping those would remove the hardest cases from H1. The snapshot itself
    is never rewritten: labels are merged here, in memory.
    """
    entries = [
        json.loads(line)
        for line in snapshot.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    check_frozen(entries, manifest_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    _check_unchanged(entries, manifest)
    queue = {str(i) for i in manifest["queue"]}
    labelled = {entry_id for records in annotations.values() for entry_id in records}
    if outside := labelled - queue:
        raise RuntimeError(f"{len(outside)} labels are for findings outside the registered queue")
    if missing := queue - labelled:
        raise RuntimeError(
            f"annotation is not complete: {len(missing)} of {len(queue)} queued findings "
            "have no label"
        )
    settled = dict(adjudicated or {})
    _, disputed = merge_human_labels(entries, annotations, adjudicated={})
    if undisputed := set(settled) - set(disputed):
        raise RuntimeError(f"{len(undisputed)} adjudications are for findings not in dispute")
    merged, conflicts = merge_human_labels(entries, annotations, adjudicated=settled)
    if conflicts:
        noun = "finding" if len(conflicts) == 1 else "findings"
        raise RuntimeError(
            f"{len(conflicts)} {noun} the annotators disagree on; adjudicate before analysing"
        )
    return merged, manifest


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the pre-registered study analysis.")
    parser.add_argument("--snapshot", type=Path, default=Path(".cache/study/snapshot.jsonl"))
    parser.add_argument("--manifest", type=Path, default=Path(".cache/study/manifest.json"))
    parser.add_argument(
        "--annotator",
        action="append",
        required=True,
        help=(
            "An annotator whose labels count as votes; repeat for each. A retest of the "
            "same person measures reliability and is never a vote."
        ),
    )
    parser.add_argument(
        "--adjudicated",
        type=Path,
        help="Settled disagreements, one JSON record per line with entry_id, label and reason.",
    )
    args = parser.parse_args(argv)
    annotations = {}
    for name in args.annotator:
        path = annotation_paths(name)[1]
        if not path.exists():
            # read_annotations treats a missing file as no labels, which here
            # would silently drop a person's votes and every conflict they raise.
            raise FileNotFoundError(f"no annotations for {name} at {path}")
        annotations[name] = read_annotations(path)
    adjudicated = read_adjudications(args.adjudicated) if args.adjudicated else None
    entries, manifest = load_study(args.snapshot, args.manifest, annotations, adjudicated=adjudicated)
    for line in study_lines(entries, manifest):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
