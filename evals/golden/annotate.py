"""Blind annotation: what a person sees, and where their judgement is kept."""

import argparse
import json
import re
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from analyzer.triage.base import as_condition, present
from evals.golden.label import KEYS, LABELS, rule_text

# An allowlist, never a denylist. The view is built from these fields alone, so
# a field added to entries later - another model's score, a reviewer's note -
# cannot leak into what the annotator sees because someone forgot to hide it.
VISIBLE_FIELDS = (
    "rule_id",
    "language",
    "context",
    "flagged_offset",
    "context_function",
    "flagged_offset_function",
)


def blind_view(entry: Mapping[str, Any], rules: Mapping[str, tuple[str, str]]) -> str:
    """The code and the claim, and nothing any judge has said about them."""
    visible = {name: entry[name] for name in VISIBLE_FIELDS if entry.get(name) is not None}
    title, description = rules[str(visible["rule_id"])]
    parts = [f"Claim: {title}", description, f"Language: {visible['language']}", ""]
    if "context_function" in visible:
        parts += ["--- the function this finding sits in ---", present(as_condition(visible, "function")), ""]
    parts += ["--- lines around the flagged line ---", present(as_condition(visible, "window"))]
    return "\n".join(parts)


def record_annotation(path: Path, entry_id: str, label: str, *, reason: str, annotator: str) -> None:
    """Append one judgement to this annotator's own file.

    Append-only, and the latest record for an entry wins, so undo is a new
    record rather than an edit. One file per annotator, so a second annotator's
    tool never opens the first's work.
    """
    if label not in LABELS:
        raise ValueError(f"label must be one of {', '.join(LABELS)}, got {label!r}")
    if not annotator.strip():
        raise ValueError("an annotation needs an annotator")
    path.parent.mkdir(parents=True, exist_ok=True)
    record = {"entry_id": entry_id, "label": label, "reason": reason, "annotator": annotator}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def read_annotations(path: Path) -> dict[str, dict[str, Any]]:
    """Each entry's latest judgement in one annotator's file."""
    latest: dict[str, dict[str, Any]] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                latest[str(record["entry_id"])] = record
    return latest


def merge_human_labels(
    entries: Sequence[Mapping[str, Any]],
    annotations: Mapping[str, Mapping[str, Mapping[str, Any]]],
    *,
    adjudicated: Mapping[str, str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Write agreed or adjudicated human labels onto the entries.

    A model's earlier label is moved to `model_label` rather than overwritten,
    because agreement between the model and the people is a figure worth
    reporting. Entries the annotators disagree on, with no adjudication, get no
    label and are returned so they can be resolved.
    """
    merged: list[dict[str, Any]] = []
    conflicts: list[str] = []
    for entry in entries:
        fresh = dict(entry)
        entry_id = str(fresh["entry_id"])
        votes = {
            annotator: str(records[entry_id]["label"])
            for annotator, records in annotations.items()
            if entry_id in records
        }
        if votes:
            if entry_id in adjudicated:
                label = adjudicated[entry_id]
            elif len(set(votes.values())) == 1:
                label = next(iter(votes.values()))
            else:
                conflicts.append(entry_id)
                merged.append(fresh)
                continue
            if label not in LABELS:
                raise ValueError(f"adjudicated label must be one of {', '.join(LABELS)}")
            if fresh.get("label") is not None and fresh.get("labelled_by") != "human":
                fresh["model_label"] = fresh["label"]
                fresh["model_reason"] = fresh.get("reason", "")
            fresh.update(label=label, labelled_by="human", annotators=sorted(votes))
        merged.append(fresh)
    return merged, conflicts


def export_blind_queue(
    entries: Sequence[Mapping[str, Any]], queue: Sequence[str], path: Path
) -> None:
    """Write the annotator's working file: the queue, in order, visible fields only.

    Stronger than hiding fields at display time. The file an annotator works from
    never contains a probability, an observation or a model's label, so there is
    nothing to see even by opening it.
    """
    by_id = {str(e["entry_id"]): e for e in entries}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for entry_id in queue:
            entry = by_id[entry_id]
            blind = {"entry_id": entry_id} | {
                name: entry[name] for name in VISIBLE_FIELDS if entry.get(name) is not None
            }
            handle.write(json.dumps(blind, sort_keys=True) + "\n")


def run_queue(
    *,
    queue_path: Path,
    annotation_path: Path,
    annotator: str,
    rules: Mapping[str, tuple[str, str]],
    ask: Callable[[str], str] = input,
    show: Callable[[str], None] = print,
) -> int:
    """Present each unjudged entry and record the answer, resuming where it stopped."""
    queue = [json.loads(line) for line in queue_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    done = read_annotations(annotation_path)
    for position, entry in enumerate(queue, start=1):
        if str(entry["entry_id"]) in done:
            continue
        show(f"\n[{position}/{len(queue)}]\n" + blind_view(entry, rules))
        answer = ""
        while answer not in KEYS:
            answer = ask("[y] real  [n] not real  [u] unsure  [q] save and quit > ").strip().lower()
            if answer == "q":
                return 0
        reason = ask("why, in one line (optional) > ").strip()
        record_annotation(
            annotation_path, str(entry["entry_id"]), KEYS[answer], reason=reason, annotator=annotator
        )
    show("Queue complete.")
    return 0


# Lower-case letters, digits and hyphens. The name becomes part of two file
# paths, so anything else - a slash, a dot - could write outside the
# annotations directory.
ANNOTATOR_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")


def annotation_paths(annotator: str) -> tuple[Path, Path]:
    """This annotator's queue and output files, refusing a name that is not one."""
    if not ANNOTATOR_NAME.fullmatch(annotator):
        raise ValueError(f"annotator must match {ANNOTATOR_NAME.pattern}, got {annotator!r}")
    return Path(f".cache/study/queue-{annotator}.jsonl"), Path(f".cache/annotations/{annotator}.jsonl")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Label findings blind to every judge's answer.")
    parser.add_argument("--annotator", required=True)
    args = parser.parse_args(argv)
    queue, out = annotation_paths(args.annotator)
    if not queue.exists():
        raise FileNotFoundError(f"no queue at {queue}; export it first")
    return run_queue(queue_path=queue, annotation_path=out, annotator=args.annotator, rules=rule_text())


if __name__ == "__main__":
    raise SystemExit(main())
