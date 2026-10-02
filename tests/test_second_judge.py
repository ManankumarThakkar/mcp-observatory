import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from analyzer.triage.base import Decision
from analyzer.triage.jev import JevAdjudicator
from evals.golden.study import (
    CONTROL_SIZE,
    STUDY_SEED,
    annotation_sample,
    probability_digest,
    snapshot_digest,
)
from evals.harness import second_judge
from evals.harness.arms import adjudicator_for
from evals.harness.second_judge import judge, main, sample_ids, summary_lines


class FixedJudge:
    """Answers by context length, so the two views can disagree, at a set price."""

    name = "fake"

    def __init__(self, cost: float = 0.01) -> None:
        self.cost = cost
        self.calls = 0

    def decide(self, entry: Mapping[str, Any]) -> Decision:
        self.calls += 1
        probability = 0.9 if len(str(entry["context"])) < 40 else 0.1
        return Decision(probability=probability, cost_usd=self.cost, latency_ms=1.0)


def _entry(i: int, server: str = "s/a") -> dict[str, Any]:
    return {
        "entry_id": f"g-{i}",
        "finding_id": f"f-{i}",
        "commit_sha": "a" * 40,
        "server_id": server,
        "rule_id": "PATH-TRAVERSAL",
        "language": "typescript",
        "context": f"  read(p{i});",
        "flagged_offset": 0,
        "context_function": f"function h{i}(p) {{\n  check(p);\n  read(p{i});\n  return 0;\n}}",
        "flagged_offset_function": 2,
        "probabilities": {"window": 0.9, "function": 0.2},
    }


def _frozen(tmp_path: Path, entries: list[dict[str, Any]]) -> tuple[Path, Path]:
    snapshot, manifest = tmp_path / "snapshot.jsonl", tmp_path / "manifest.json"
    snapshot.write_text("".join(json.dumps(e) + "\n" for e in entries))
    sample = annotation_sample(entries, control_size=CONTROL_SIZE, seed=STUDY_SEED)
    manifest.write_text(
        json.dumps(
            {
                "digest": snapshot_digest(entries),
                "probability_digest": probability_digest(entries),
                "queue": sample.queue,
                "disagreement": sorted(sample.disagreement),
                "control": sorted(sample.control),
                "sample_seed": STUDY_SEED,
            }
        )
    )
    return snapshot, manifest


def test_the_default_arm_is_the_decision_model() -> None:
    assert isinstance(adjudicator_for("jev"), JevAdjudicator)


def test_an_unknown_arm_is_refused() -> None:
    with pytest.raises(ValueError, match="oracle"):
        adjudicator_for("oracle")


def test_both_views_are_judged_and_the_spend_is_counted(tmp_path: Path) -> None:
    results = judge([_entry(1), _entry(2)], adjudicator=FixedJudge(), cache_path=tmp_path / "c.jsonl", max_cost=1.0)
    assert results.answers == {
        "g-1": {"window": 0.9, "function": 0.1},
        "g-2": {"window": 0.9, "function": 0.1},
    }
    assert results.cost_usd == pytest.approx(0.04)


def test_the_run_stops_once_spend_reaches_the_cap(tmp_path: Path) -> None:
    fake = FixedJudge(cost=0.5)
    results = judge([_entry(i) for i in range(5)], adjudicator=fake, cache_path=tmp_path / "c.jsonl", max_cost=1.0)
    assert fake.calls == 2
    assert results.stopped_at_cap


def test_answers_already_paid_for_are_not_paid_for_again(tmp_path: Path) -> None:
    cache = tmp_path / "c.jsonl"
    judge([_entry(1)], adjudicator=FixedJudge(), cache_path=cache, max_cost=1.0)
    again = FixedJudge()
    judge([_entry(1)], adjudicator=again, cache_path=cache, max_cost=1.0)
    assert again.calls == 0


def test_the_sample_is_reproducible_and_drawn_from_paired_findings() -> None:
    entries = [_entry(i) for i in range(30)] + [{**_entry(99), "context_function": None}]
    first = sample_ids(entries, 5)
    assert first == sample_ids(list(reversed(entries)), 5)
    assert "g-99" not in first and len(first) == 5


def test_the_summary_is_labelled_exploratory_and_compares_with_the_first_judge() -> None:
    entries = [_entry(i, server=f"s/{i}") for i in range(4)]
    answers = {e["entry_id"]: {"window": 0.9, "function": 0.1} for e in entries}
    lines = summary_lines(entries, answers, arm="frontier", seed=1)
    assert lines[0].startswith("EXPLORATORY")
    assert any("4 of 4 paired findings" in line for line in lines)
    assert any("agree with the first judge" in line for line in lines)


def test_the_frozen_snapshot_is_never_written(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, manifest = _frozen(tmp_path, [_entry(i) for i in range(3)])
    before = snapshot.read_bytes()
    monkeypatch.setattr(second_judge, "adjudicator_for", lambda arm: FixedJudge())
    out = tmp_path / "arms"
    argv = ["--arm", "frontier", "--snapshot", str(snapshot), "--manifest", str(manifest), "--out", str(out)]
    assert main([*argv, "--sample", "2"]) == 0
    assert main([*argv, "--max-cost", "1"]) == 0
    assert snapshot.read_bytes() == before
    assert len((out / "frontier.jsonl").read_text().splitlines()) == 3


def test_a_full_run_needs_a_measured_sample_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, manifest = _frozen(tmp_path, [_entry(i) for i in range(3)])
    monkeypatch.setattr(second_judge, "adjudicator_for", lambda arm: FixedJudge())
    argv = ["--arm", "frontier", "--snapshot", str(snapshot), "--manifest", str(manifest), "--out", str(tmp_path / "a")]
    with pytest.raises(RuntimeError, match="measure a sample first"):
        main([*argv, "--max-cost", "1"])


def test_a_full_run_projected_over_the_cap_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, manifest = _frozen(tmp_path, [_entry(i) for i in range(10)])
    monkeypatch.setattr(second_judge, "adjudicator_for", lambda arm: FixedJudge(cost=0.5))
    argv = ["--arm", "frontier", "--snapshot", str(snapshot), "--manifest", str(manifest), "--out", str(tmp_path / "a")]
    main([*argv, "--sample", "1"])
    with pytest.raises(RuntimeError, match="projected"):
        main([*argv, "--max-cost", "2"])


def test_the_summary_also_measures_movement_without_a_threshold() -> None:
    # A judge that scores every finding below 0.5 can never flip at the midpoint,
    # which says nothing about whether context moves it. The shift in probability
    # between the views needs no threshold.
    entries = [_entry(i, server=f"s/{i}") for i in range(6)]
    answers = {e["entry_id"]: {"window": 0.30, "function": 0.10} for e in entries}
    lines = summary_lines(entries, answers, arm="frontier", seed=1)
    shift = next(line for line in lines if "lower with the whole function" in line)
    assert "6 lower" in shift
    assert "0 higher" in shift
    assert "median shift -0.20" in shift
    assert any(line.strip().startswith("first judge, same findings:") for line in lines)


class FailingJudge(FixedJudge):
    """Refuses one finding, as a model may."""

    def decide(self, entry: Mapping[str, Any]) -> Decision:
        if "read(p1)" in str(entry["context"]):
            raise ValueError(f"the model refused to answer for {entry['entry_id']}")
        return super().decide(entry)


def test_a_failed_call_is_reported_with_its_reason_not_dropped(tmp_path: Path) -> None:
    # A refusal repeats on every retry and a network blip does not, so the
    # reason decides what to do next; dropping it hides which happened.
    results = judge([_entry(1), _entry(2)], adjudicator=FailingJudge(), cache_path=tmp_path / "c.jsonl", max_cost=1.0)
    assert "g-1" not in results.answers
    assert list(results.failures.values()) == [
        "ValueError: the model refused to answer for g-1",
        "ValueError: the model refused to answer for g-1",
    ]
