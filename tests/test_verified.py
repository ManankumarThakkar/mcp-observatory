import json
from pathlib import Path

import pytest

from evals.golden.verified import human_true_positives

ENTRIES = [
    {"entry_id": "g-1", "finding_id": "f-1"},
    {"entry_id": "g-2", "finding_id": "f-2"},
    {"entry_id": "g-3", "finding_id": "f-3"},
]


def _annotations(tmp_path: Path, *records: tuple[str, str]) -> Path:
    path = tmp_path / "manan.jsonl"
    path.write_text(
        "".join(
            json.dumps({"entry_id": e, "label": label, "reason": "", "annotator": "manan"}) + "\n"
            for e, label in records
        )
    )
    return path


def test_only_findings_a_person_labelled_true_positive_count(tmp_path: Path) -> None:
    path = _annotations(
        tmp_path, ("g-1", "true_positive"), ("g-2", "false_positive"), ("g-3", "unsure")
    )
    assert human_true_positives(path, ENTRIES) == frozenset({"f-1"})


def test_the_latest_label_wins_so_an_undo_counts(tmp_path: Path) -> None:
    path = _annotations(tmp_path, ("g-1", "true_positive"), ("g-1", "false_positive"))
    assert human_true_positives(path, ENTRIES) == frozenset()


def test_a_missing_annotation_file_is_refused_not_read_as_nothing_verified(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="nobody.jsonl"):
        human_true_positives(tmp_path / "nobody.jsonl", ENTRIES)
