from pathlib import Path
from typing import Any

import pytest

from evals.golden.annotate import (
    annotation_paths,
    blind_view,
    export_blind_queue,
    merge_human_labels,
    read_annotations,
    record_annotation,
    run_queue,
)
from evals.golden.label import rule_text


def _entry(entry_id: str, window: float = 0.8, function: float = 0.8, **extra: Any) -> dict[str, Any]:
    return {
        "entry_id": entry_id, "finding_id": f"f-{entry_id}", "commit_sha": "a" * 40,
        "rule_id": "SHELL-EXEC-UNSAFE", "language": "typescript", "server_id": "s/x",
        "context": "  run(cmd);", "flagged_offset": 0,
        "context_function": "function h(p) {\n  run(p);\n}", "flagged_offset_function": 1,
        "probabilities": {"window": window, "function": function}, **extra,
    }


def test_the_view_shows_no_judge_s_opinion() -> None:
    entry = _entry(
        "g-1", window=0.1234, function=0.9876,
        observations={"window": {"label": "false_positive", "reason": "SENTINEL-OBS"}},
        label="true_positive", reason="SENTINEL-REASON", labelled_by="model",
        severity="critical", confidence="high", file="SENTINEL/PATH.ts", server_id="SENTINEL/SERVER",
    )
    view = blind_view(entry, rule_text())
    for leaked in ("0.1234", "0.9876", "SENTINEL", "critical", "high", "true_positive", "false_positive", "model"):
        assert leaked not in view, leaked
    assert "run(p);" in view and "run(cmd);" in view


def test_the_latest_judgement_wins_and_each_annotator_has_their_own_file(tmp_path: Path) -> None:
    first, second = tmp_path / "first.jsonl", tmp_path / "second.jsonl"
    record_annotation(first, "g-1", "true_positive", reason="x", annotator="first")
    record_annotation(first, "g-1", "false_positive", reason="changed my mind", annotator="first")
    record_annotation(second, "g-1", "unsure", reason="y", annotator="second")
    assert read_annotations(first)["g-1"]["label"] == "false_positive"
    assert read_annotations(second)["g-1"]["label"] == "unsure"


def test_an_unknown_label_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        record_annotation(tmp_path / "a.jsonl", "g-1", "probably", reason="x", annotator="a")


def test_merge_writes_agreement_keeps_the_model_label_and_reports_conflicts() -> None:
    entries = [_entry("g-1", label="false_positive", labelled_by="model", reason="claude says"), _entry("g-2")]
    annotations = {
        "first": {"g-1": {"label": "true_positive"}, "g-2": {"label": "true_positive"}},
        "second": {"g-1": {"label": "true_positive"}, "g-2": {"label": "false_positive"}},
    }
    merged, conflicts = merge_human_labels(entries, annotations, adjudicated={})
    assert merged[0]["label"] == "true_positive" and merged[0]["labelled_by"] == "human"
    assert merged[0]["model_label"] == "false_positive"
    assert merged[0]["annotators"] == ["first", "second"]
    assert conflicts == ["g-2"] and merged[1].get("labelled_by") is None


def test_adjudication_settles_a_conflict() -> None:
    annotations = {"first": {"g-2": {"label": "true_positive"}}, "second": {"g-2": {"label": "false_positive"}}}
    merged, conflicts = merge_human_labels([_entry("g-2")], annotations, adjudicated={"g-2": "false_positive"})
    assert conflicts == [] and merged[0]["label"] == "false_positive"


def test_the_exported_queue_file_holds_no_judge_s_output(tmp_path: Path) -> None:
    entry = _entry("g-1", label="true_positive", labelled_by="model", reason="r",
                   observations={"window": {"label": "false_positive"}}, severity="critical")
    path = tmp_path / "queue.jsonl"
    export_blind_queue([entry], ["g-1"], path)
    text = path.read_text()
    for leaked in ("probabilities", "observations", "label", "reason", "severity", "server_id"):
        assert f'"{leaked}"' not in text, leaked
    assert "run(cmd);" in text


def test_the_loop_records_answers_and_resumes_after_quitting(tmp_path: Path) -> None:
    queue_path, notes = tmp_path / "queue.jsonl", tmp_path / "manan.jsonl"
    export_blind_queue([_entry("g-1"), _entry("g-2")], ["g-1", "g-2"], queue_path)
    answers = iter(["y", "reads the parameter straight in", "q"])
    run_queue(queue_path=queue_path, annotation_path=notes, annotator="manan", rules=rule_text(),
              ask=lambda _p: next(answers), show=lambda _t: None)
    assert read_annotations(notes) == {
        "g-1": {"entry_id": "g-1", "label": "true_positive", "reason": "reads the parameter straight in", "annotator": "manan"}
    }
    shown: list[str] = []
    more = iter(["n", ""])
    run_queue(queue_path=queue_path, annotation_path=notes, annotator="manan", rules=rule_text(),
              ask=lambda _p: next(more), show=shown.append)
    assert read_annotations(notes)["g-2"]["label"] == "false_positive"
    assert not any("[1/2]" in s for s in shown), "a finished entry was shown again"



def test_an_annotator_name_cannot_escape_the_annotations_directory() -> None:
    """The name becomes part of a file path, so it is refused rather than escaped."""
    for bad in ("../x", "a/b", "Manan", "", "a.b"):
        with pytest.raises(ValueError):
            annotation_paths(bad)
    assert annotation_paths("manan")[1] == Path(".cache/annotations/manan.jsonl")
