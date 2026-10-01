"""Which findings a person has verified, for the disclosure ledger.

The approved policy notifies maintainers only of findings a person labelled a
true positive. The labels live here, beside the tool that records them, so the
ledger asks this module rather than reading annotation files itself.
"""

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from evals.golden.annotate import read_annotations


def human_true_positives(
    annotation_path: Path, entries: Sequence[Mapping[str, Any]]
) -> frozenset[str]:
    """Finding ids whose latest label in this person's file is a true positive.

    A missing file is refused: a misspelt annotator would otherwise read as a
    person who verified nothing, and the reason every notice was refused would
    be invisible.
    """
    if not annotation_path.exists():
        raise FileNotFoundError(f"no annotations at {annotation_path}")
    labels = read_annotations(annotation_path)
    return frozenset(
        str(entry["finding_id"])
        for entry in entries
        if labels.get(str(entry["entry_id"]), {}).get("label") == "true_positive"
    )
