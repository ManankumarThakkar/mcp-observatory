from pathlib import Path
from typing import Any

import pytest

from analyzer.triage.base import Decision
from analyzer.triage.cache import MAX_CALLS_PER_RUN, TriageCache, adjudicate, cache_key


def _entry(n: int, context: str = "c") -> dict[str, Any]:
    return {
        "entry_id": f"g-{n}",
        "rule_id": "R",
        "evidence": f"e{n}",
        "context": context,
        "language": "typescript",
        "flagged_offset": 0,
    }


class _Counting:
    name = "counting"

    def __init__(self) -> None:
        self.calls = 0

    def decide(self, entry: Any) -> Decision:
        self.calls += 1
        return Decision(probability=0.9, cost_usd=0.001, latency_ms=1.0)


def test_the_same_finding_in_the_same_code_is_asked_once() -> None:
    assert cache_key("R", "evidence", "context") == cache_key("R", "evidence", "context")


def test_identical_evidence_in_different_code_is_a_different_question() -> None:
    """A deliberate deviation from spec section 6.4, which keys on rule and
    evidence alone. The adjudicator judges from the window, so that key would
    give two genuinely different findings one shared verdict - and the window
    is precisely what separates a reachable call from a safe one.
    """
    assert cache_key("R", "exec(cmd)", "cmd = 'ls'") != cache_key("R", "exec(cmd)", "cmd = req.body.x")


def test_the_separator_cannot_be_impersonated_by_the_content() -> None:
    """Evidence and context both come from a repository we do not control. If
    they were joined raw, a value containing the separator could shift the
    boundary and two different findings would share one cached verdict.
    """
    assert cache_key("R", "a", "b|c") != cache_key("R", "a|b", "c")


def test_a_cached_verdict_costs_no_call(tmp_path: Path) -> None:
    """Nightly runs approach zero because finding_id is deterministic and
    unchanged findings hit the cache. Without this the bill recurs nightly."""
    adjudicator = _Counting()
    cache = TriageCache(tmp_path / "triage.jsonl")

    adjudicate([_entry(1)], adjudicator=adjudicator, cache=cache, max_calls=10)
    adjudicate([_entry(1)], adjudicator=adjudicator, cache=cache, max_calls=10)

    assert adjudicator.calls == 1


def test_a_cached_verdict_survives_a_new_process(tmp_path: Path) -> None:
    """A cache only in memory would re-spend the entire bill on every run,
    which is the failure it exists to prevent."""
    path = tmp_path / "triage.jsonl"
    adjudicate([_entry(1)], adjudicator=_Counting(), cache=TriageCache(path), max_calls=10)

    second = _Counting()
    adjudicate([_entry(1)], adjudicator=second, cache=TriageCache(path), max_calls=10)

    assert second.calls == 0


def test_the_spend_guard_stops_calling_and_completes_the_run(tmp_path: Path) -> None:
    """Spec section 12: past the cap, mark the remainder uncertain and finish.
    Aborting would publish nothing and look like a broken scanner."""
    entries = [_entry(n) for n in range(5)]

    results = adjudicate(
        entries, adjudicator=_Counting(), cache=TriageCache(tmp_path / "t.jsonl"), max_calls=2
    )

    assert sum(1 for d in results.values() if d is not None) == 2
    assert sum(1 for d in results.values() if d is None) == 3


def test_cached_entries_do_not_consume_the_spend_guard(tmp_path: Path) -> None:
    """The cap counts calls, not findings. Counting cached hits against it
    would shrink what a nightly run adjudicates for no reason, and the shrink
    would grow as the cache filled - exactly backwards."""
    cache = TriageCache(tmp_path / "t.jsonl")
    adjudicate([_entry(0)], adjudicator=_Counting(), cache=cache, max_calls=10)

    fresh = _Counting()
    results = adjudicate([_entry(n) for n in range(3)], adjudicator=fresh, cache=cache, max_calls=2)

    assert fresh.calls == 2
    assert all(d is not None for d in results.values())


def test_the_cap_is_the_documented_one() -> None:
    """Spec section 12 states 3,000. If it moves, the spec moves with it."""
    assert MAX_CALLS_PER_RUN == 3_000


def test_a_corrupt_cache_names_the_line_rather_than_resetting(tmp_path: Path) -> None:
    """A silent reset would re-spend the entire cached bill and nothing would
    say why - the same failure the findings history already guards against."""
    path = tmp_path / "triage.jsonl"
    path.write_text('{"key": "a", "probability": 0.5, "cost_usd": 0.0}\nnot json\n', encoding="utf-8")

    with pytest.raises(ValueError, match="line 2"):
        TriageCache(path).get("a")


def test_a_failed_adjudication_is_not_cached(tmp_path: Path) -> None:
    """Caching a failure would make one outage permanent, and the finding
    would never be adjudicated again."""

    class Failing:
        name = "failing"

        def decide(self, entry: Any) -> Decision:
            raise RuntimeError("service unavailable")

    cache = TriageCache(tmp_path / "t.jsonl")
    with pytest.raises(RuntimeError):
        adjudicate([_entry(1)], adjudicator=Failing(), cache=cache, max_calls=10)

    assert cache.get(cache_key("R", "e1", "c")) is None
