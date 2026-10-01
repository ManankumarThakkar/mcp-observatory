from pathlib import Path
from typing import Any

import pytest

from evals.golden.study import (
    annotation_sample,
    check_frozen,
    probability_digest,
    snapshot_digest,
)


def _entry(entry_id: str, window: float = 0.8, function: float = 0.8, **extra: Any) -> dict[str, Any]:
    return {
        "entry_id": entry_id, "finding_id": f"f-{entry_id}", "commit_sha": "a" * 40,
        "rule_id": "SHELL-EXEC-UNSAFE", "language": "typescript", "server_id": "s/x",
        "context": "  run(cmd);", "flagged_offset": 0,
        "context_function": "function h(p) {\n  run(p);\n}", "flagged_offset_function": 1,
        "probabilities": {"window": window, "function": function}, **extra,
    }


def test_digest_ignores_order_and_annotations_but_not_code() -> None:
    a, b = _entry("g-1"), _entry("g-2")
    base = snapshot_digest([a, b])
    assert snapshot_digest([b, a]) == base
    assert snapshot_digest([{**a, "label": "true_positive", "labelled_by": "human"}, b]) == base
    assert snapshot_digest([{**a, "context": "  run(other);"}, b]) != base


def test_sample_holds_every_disagreement_and_a_control() -> None:
    entries = [_entry(f"d{n}", 0.8, 0.2) for n in range(10)] + [_entry(f"a{n}") for n in range(30)]
    sample = annotation_sample(entries, control_size=8, seed=11)
    assert sample.disagreement == {f"d{n}" for n in range(10)}
    assert len(sample.control) == 8
    assert set(sample.queue) == sample.disagreement | sample.control
    assert len(sample.queue) == len(set(sample.queue))


def test_the_queue_does_not_put_the_disputed_findings_first() -> None:
    entries = [_entry(f"d{n}", 0.8, 0.2) for n in range(10)] + [_entry(f"a{n}") for n in range(30)]
    sample = annotation_sample(entries, control_size=10, seed=11)
    head = sample.queue[: len(sample.disagreement)]
    assert not set(head) <= sample.disagreement


def test_a_changed_snapshot_is_refused(tmp_path: Path) -> None:
    import json
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"digest": snapshot_digest([_entry("g-1")])}))
    check_frozen([_entry("g-1")], manifest)
    with pytest.raises(RuntimeError, match="changed after freezing"):
        check_frozen([{**_entry("g-1"), "context": "  run(other);"}], manifest)


def test_probability_digest_ignores_labels_but_not_a_judge_s_answer() -> None:
    # The snapshot digest leaves probabilities out so labelling cannot change it.
    # This second digest is what stops a re-run judge rewriting the answers
    # every hypothesis is computed from.
    a, b = _entry("g-1"), _entry("g-2", 0.3, 0.6)
    base = probability_digest([a, b])
    assert probability_digest([b, a]) == base
    assert probability_digest([{**a, "label": "false_positive", "labelled_by": "human"}, b]) == base
    assert probability_digest([{**a, "probabilities": {"window": 0.81, "function": 0.8}}, b]) != base
