"""The frozen study: what was measured, fixed before anyone labels it."""

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from analyzer.sampling import draw
from evals.harness.experiment import verdict

# The fields that define what a judge was shown. Deliberately excludes every
# field written afterwards - probabilities, observations, labels - so that
# labelling the frozen set does not change its digest, while a re-draw that
# changed any shown code does.
FROZEN_FIELDS = ("entry_id", "finding_id", "commit_sha", "context", "context_function")

# Registered in docs/study/preregistration.md: the sample, the bootstrap and the
# one-per-server choice all use this seed, and the control has this size.
STUDY_SEED = 20260926
CONTROL_SIZE = 60


def _digest(entries: Sequence[Mapping[str, Any]], fields: Sequence[str]) -> str:
    """One hash over the named fields of every entry, in a fixed order.

    Each field is hashed before being combined, the same guard `finding_id`
    uses, so content from a third-party repository cannot forge a boundary
    between two fields.
    """
    combined = hashlib.sha256()
    for entry in sorted(entries, key=lambda e: str(e["entry_id"])):
        for name in fields:
            value = json.dumps(entry.get(name), sort_keys=True)
            combined.update(hashlib.sha256(value.encode()).digest())
    return combined.hexdigest()


def snapshot_digest(entries: Sequence[Mapping[str, Any]]) -> str:
    """One hash over exactly what the judges were shown."""
    return _digest(entries, FROZEN_FIELDS)


def probability_digest(entries: Sequence[Mapping[str, Any]]) -> str:
    """One hash over the judges' stored answers, which every hypothesis uses.

    Kept apart from `snapshot_digest`, which deliberately leaves them out, so
    that the registered digest describes only what the judges were shown.
    """
    return _digest(entries, ("entry_id", "probabilities"))


def _identity(entry: Mapping[str, Any]) -> tuple[str, ...]:
    return (str(entry["entry_id"]),)


@dataclass(frozen=True)
class AnnotationSample:
    queue: list[str]
    disagreement: frozenset[str]
    control: frozenset[str]


def annotation_sample(
    entries: Sequence[Mapping[str, Any]], *, control_size: int, seed: int
) -> AnnotationSample:
    """Every disagreement, a random control, and one shuffled queue for both.

    The control is drawn from all paired entries, disagreements included, so it
    estimates the population rather than the easy cases; calibration is measured
    on it alone for that reason. The queue interleaves the two sets by hashed
    identity, so an annotator cannot tell a disputed finding from a control by
    where it appears.
    """
    paired = [
        e
        for e in entries
        if isinstance((e.get("probabilities") or {}).get("window"), int | float)
        and isinstance((e.get("probabilities") or {}).get("function"), int | float)
    ]
    disagreement = frozenset(
        str(e["entry_id"])
        for e in paired
        if verdict(float(e["probabilities"]["window"]))
        != verdict(float(e["probabilities"]["function"]))
    )
    control = frozenset(
        str(e["entry_id"]) for e in draw(paired, control_size, seed=seed, key=_identity)
    )
    chosen = [e for e in paired if str(e["entry_id"]) in disagreement | control]
    queue = [str(e["entry_id"]) for e in draw(chosen, len(chosen), seed=seed + 1, key=_identity)]
    return AnnotationSample(queue=queue, disagreement=disagreement, control=control)


def check_frozen(entries: Sequence[Mapping[str, Any]], manifest_path: Path) -> None:
    """Refuse to analyse a study set that is no longer the one registered.

    A re-draw against current rules silently drops or changes entries - the
    SCOPE-OVERBROAD fix made some vanish - and labels made on the old set would
    then be scored against different code without anything saying so.
    """
    expected = json.loads(manifest_path.read_text(encoding="utf-8"))["digest"]
    if snapshot_digest(entries) != expected:
        raise RuntimeError(f"the study snapshot changed after freezing ({manifest_path})")
