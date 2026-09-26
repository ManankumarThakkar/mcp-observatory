"""The runner's plumbing, exercised without a network or a paid call."""

import json
from pathlib import Path
from typing import Any

from analyzer.triage.base import Decision, present
from evals.harness.context_experiment import run


class _Recording:
    """An adjudicator that answers from what it was shown, and remembers it.

    Answering from the text is the point: if the runner failed to project the
    entry onto the second condition, both conditions would be shown the same
    window and this returns the same probability twice - which is exactly the
    silent failure the experiment cannot afford.
    """

    name = "recording"

    def __init__(self) -> None:
        self.shown: list[str] = []

    def decide(self, entry: Any) -> Decision:
        window = present(entry)
        self.shown.append(window)
        # Decisive when the enclosing function is visible, undecided otherwise.
        probability = 0.95 if "function handler" in window else 0.51
        return Decision(probability=probability, cost_usd=0.0003, latency_ms=700.0)


def _entries() -> list[dict[str, Any]]:
    return [
        {
            "entry_id": "g-0001",
            "rule_id": "SHELL-EXEC-UNSAFE",
            "language": "typescript",
            "context": "  run(cmd);",
            "flagged_offset": 0,
            "context_function": "function handler(p) {\n  const cmd = p.name;\n  run(cmd);\n}",
            "flagged_offset_function": 2,
        },
        {
            "entry_id": "g-0002",
            "rule_id": "UNICODE-CONCEAL",
            "language": "typescript",
            "context": "  const a = 1;",
            "flagged_offset": 0,
        },
    ]


def _write(path: Path, entries: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(e, sort_keys=True) + "\n" for e in entries), encoding="utf-8"
    )


def test_each_condition_is_asked_from_its_own_context(tmp_path: Path) -> None:
    """The failure this guards against is the whole experiment reporting no
    effect because it never actually showed the second context."""
    path = tmp_path / "entries.jsonl"
    _write(path, _entries())
    adjudicator = _Recording()

    run(
        path,
        cache_path=tmp_path / "cache.jsonl",
        max_calls=100,
        adjudicator=adjudicator,
    )

    assert any("function handler" in shown for shown in adjudicator.shown), (
        "the function condition was never presented"
    )
    assert any("function handler" not in shown for shown in adjudicator.shown)


def test_both_conditions_land_on_the_entry(tmp_path: Path) -> None:
    """Written back after each condition, so an interrupted run does not have to
    pay for its answers twice."""
    path = tmp_path / "entries.jsonl"
    _write(path, _entries())

    run(path, cache_path=tmp_path / "cache.jsonl", max_calls=100, adjudicator=_Recording())

    written = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    taint = next(e for e in written if e["entry_id"] == "g-0001")
    assert set(taint["probabilities"]) == {"window", "function"}
    assert taint["probabilities"]["function"] > taint["probabilities"]["window"]


def test_an_entry_with_no_enclosing_function_is_judged_once_only(tmp_path: Path) -> None:
    """A rule whose findings sit at the top level of a file has no second
    condition, and inventing one would put a duplicate of the window into the
    comparison as though it were a different context."""
    path = tmp_path / "entries.jsonl"
    _write(path, _entries())

    run(path, cache_path=tmp_path / "cache.jsonl", max_calls=100, adjudicator=_Recording())

    written = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    control = next(e for e in written if e["entry_id"] == "g-0002")
    assert set(control["probabilities"]) == {"window"}


def test_the_control_group_is_reported_separately(tmp_path: Path) -> None:
    """The placebo has to be reported, not merely captured: an effect measured
    only on the predicted group cannot rule out more text reading as more
    evidence."""
    path = tmp_path / "entries.jsonl"
    _write(path, _entries())

    predicted, control = run(
        path, cache_path=tmp_path / "cache.jsonl", max_calls=100, adjudicator=_Recording()
    )

    assert predicted["predicted"].n == 1
    assert control["control"].n == 0
