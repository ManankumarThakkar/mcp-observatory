from pathlib import Path
from typing import Any

import pytest

from analyzer.triage.base import Decision
from analyzer.triage.cache import MAX_CALLS_PER_RUN, TriageCache, adjudicate, cache_key


def _entry(n: int, context: str | None = None) -> dict[str, Any]:
    # A distinct window per entry, because the key is over what the model is
    # sent: entries sharing a window are the same question by definition, and
    # a fixture that reused one would make the cache look broken.
    return {
        "entry_id": f"g-{n}",
        "rule_id": "R",
        "context": context if context is not None else f"line {n}\nexec(cmd{n})",
        "language": "typescript",
        "flagged_offset": 1,
    }


class _Counting:
    name = "counting"

    def __init__(self) -> None:
        self.calls = 0

    def decide(self, entry: Any) -> Decision:
        self.calls += 1
        return Decision(probability=0.9, cost_usd=0.001, latency_ms=1.0)


def test_the_same_finding_in_the_same_code_is_asked_once() -> None:
    entry = {"rule_id": "R", "language": "typescript", "context": "a", "flagged_offset": 0}

    assert cache_key("arm", entry) == cache_key("arm", dict(entry))


def test_identical_evidence_in_different_code_is_a_different_question() -> None:
    """A deliberate deviation from spec section 6.4, which keys on rule and
    evidence alone. The adjudicator judges from the window, so that key would
    give two genuinely different findings one shared verdict - and the window
    is precisely what separates a reachable call from a safe one.
    """
    base = {"rule_id": "R", "language": "typescript", "flagged_offset": 1}

    assert cache_key("arm", {**base, "context": "cmd = 'ls'\nexec(cmd)"}) != cache_key(
        "arm", {**base, "context": "cmd = req.body.x\nexec(cmd)"}
    )


def test_the_separator_cannot_be_impersonated_by_the_content() -> None:
    """Evidence and context both come from a repository we do not control. If
    they were joined raw, a value containing the separator could shift the
    boundary and two different findings would share one cached verdict.
    """
    base = {"rule_id": "R", "language": "typescript", "flagged_offset": 0}

    assert cache_key("arm", {**base, "context": "a|b"}) != cache_key("arm|b", {**base, "context": "a"})


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

    assert sum(1 for d in results.decisions.values() if d is not None) == 2
    assert sum(1 for d in results.decisions.values() if d is None) == 3


def test_cached_entries_do_not_consume_the_spend_guard(tmp_path: Path) -> None:
    """The cap counts calls, not findings. Counting cached hits against it
    would shrink what a nightly run adjudicates for no reason, and the shrink
    would grow as the cache filled - exactly backwards."""
    cache = TriageCache(tmp_path / "t.jsonl")
    adjudicate([_entry(0)], adjudicator=_Counting(), cache=cache, max_calls=10)

    fresh = _Counting()
    results = adjudicate([_entry(n) for n in range(3)], adjudicator=fresh, cache=cache, max_calls=2)

    assert fresh.calls == 2
    assert all(d is not None for d in results.decisions.values())


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
    result = adjudicate([_entry(1)], adjudicator=Failing(), cache=cache, max_calls=10)

    assert cache.get(cache_key("failing", _entry(1))) is None
    assert result.failures  # isolated and reported, rather than raised


class _Fixed:
    """An arm that always answers the same thing, so a mix-up is visible."""

    def __init__(self, name: str, probability: float) -> None:
        self.name = name
        self._probability = probability

    def decide(self, entry: Any) -> Decision:
        return Decision(probability=self._probability, cost_usd=0.001, latency_ms=1.0)


def test_two_arms_do_not_read_each_other_s_answers(tmp_path: Path) -> None:
    """The benchmark's entire purpose is comparing arms. Without the arm in
    the key, the second one run would read the first's decisions from the
    cache and report identical precision - a plausible-looking result with
    nothing to indicate it was never measured.
    """
    cache = TriageCache(tmp_path / "t.jsonl")
    entries = [_entry(1)]

    first = adjudicate(entries, adjudicator=_Fixed("arm-a", 0.9), cache=cache, max_calls=10)
    second = adjudicate(entries, adjudicator=_Fixed("arm-b", 0.1), cache=cache, max_calls=10)

    assert first.decisions["g-1"] is not None and first.decisions["g-1"].probability == 0.9
    assert second.decisions["g-1"] is not None and second.decisions["g-1"].probability == 0.1


def test_the_same_arm_still_reuses_its_own_answer(tmp_path: Path) -> None:
    cache = TriageCache(tmp_path / "t.jsonl")
    counting = _Counting()

    adjudicate([_entry(1)], adjudicator=counting, cache=cache, max_calls=10)
    adjudicate([_entry(1)], adjudicator=counting, cache=cache, max_calls=10)

    assert counting.calls == 1


def test_a_real_golden_entry_can_be_adjudicated(tmp_path: Path) -> None:
    """The entries the sampler writes carry no `evidence` field, so a key that
    read one raised KeyError on every real entry. Two components that each
    worked and did not join up.
    """
    entry = {
        "entry_id": "g-0001",
        "finding_id": "abc",
        "rule_id": "R",
        "severity": "high",
        "confidence": "low",
        "language": "typescript",
        "context": "a\nb\nc",
        "flagged_offset": 1,
        "label": None,
    }

    results = adjudicate(
        [entry], adjudicator=_Counting(), cache=TriageCache(tmp_path / "t.jsonl"), max_calls=10
    )

    assert results.decisions["g-0001"] is not None


def test_the_key_is_over_what_the_model_is_actually_sent(tmp_path: Path) -> None:
    """Evidence never reaches the model, so keying on it would treat two
    identical questions as different and pay twice. What varies the answer is
    the rule, the language and the marked window."""
    base = {"rule_id": "R", "language": "typescript", "context": "a\nb", "flagged_offset": 0}

    assert cache_key("arm", base) == cache_key("arm", {**base, "evidence": "anything"})
    assert cache_key("arm", base) != cache_key("arm", {**base, "flagged_offset": 1})
    assert cache_key("arm", base) != cache_key("arm", {**base, "language": "python"})


class _FailingOn:
    """An arm that fails for chosen entries and answers the rest."""

    name = "flaky"

    def __init__(self, failing: set[str]) -> None:
        self.failing = failing
        self.asked: list[str] = []

    def decide(self, entry: Any) -> Decision:
        self.asked.append(str(entry["entry_id"]))
        if str(entry["entry_id"]) in self.failing:
            raise RuntimeError("the decision model was unreachable after 4 attempts")
        return Decision(probability=0.9, cost_usd=0.0003, latency_ms=700.0)


def test_one_unreachable_entry_does_not_discard_the_rest_of_the_run(tmp_path: Path) -> None:
    """Measured against a degraded service: a single entry exhausting its
    retries aborted a two-hundred-call run, and over that many calls against a
    service answering in tens of seconds it was near-certain to happen. The
    orchestrator already isolates one bad repository from a corpus run for the
    same reason; an adjudication run has no claim to be different.
    """
    entries = [_entry(n) for n in range(4)]
    for number, entry in enumerate(entries):
        entry["entry_id"] = f"g-{number}"
    arm = _FailingOn({"g-1"})

    result = adjudicate(
        entries, adjudicator=arm, cache=TriageCache(tmp_path / "t.jsonl"), max_calls=10
    )

    assert arm.asked == ["g-0", "g-1", "g-2", "g-3"], "the run stopped at the failure"
    assert result.decisions["g-1"] is None
    assert [result.decisions[f"g-{n}"] is not None for n in (0, 2, 3)] == [True] * 3


def test_a_failure_is_reported_apart_from_an_entry_the_guard_never_reached(
    tmp_path: Path,
) -> None:
    """Both end up without an answer, and the two call for different actions: one
    is re-run, the other needs the cap raised. Reporting a failed call as a
    budget decision would state a reason that is simply untrue."""
    entries = [_entry(n) for n in range(3)]
    for number, entry in enumerate(entries):
        entry["entry_id"] = f"g-{number}"

    result = adjudicate(
        entries,
        adjudicator=_FailingOn({"g-0"}),
        cache=TriageCache(tmp_path / "t.jsonl"),
        max_calls=1,
    )

    assert set(result.failures) == {"g-0"}
    assert "unreachable" in result.failures["g-0"]
    # g-0 failed without being billed, so g-1 took the single call and g-2 is
    # the one the cap stopped short of.
    assert result.decisions["g-1"] is not None
    assert result.decisions["g-2"] is None
    assert "g-2" not in result.failures


def test_a_run_reports_what_it_spent(tmp_path: Path) -> None:
    """The project publishes cost per decision, and a figure reconstructed later
    from a price list is an estimate wearing a measurement's clothes."""
    entries = [_entry(n) for n in range(3)]
    for number, entry in enumerate(entries):
        entry["entry_id"] = f"g-{number}"

    result = adjudicate(
        entries,
        adjudicator=_FailingOn(set()),
        cache=TriageCache(tmp_path / "t.jsonl"),
        max_calls=10,
    )

    assert result.calls == 3
    assert result.cost_usd == pytest.approx(3 * 0.0003)


def test_a_failed_call_does_not_consume_the_spend_guard(tmp_path: Path) -> None:
    """The cap bounds money, and a call that failed was not billed. Counting it
    would let a degraded service silently shrink how much of a run gets
    adjudicated, and the shrink would be worst exactly when the retries are
    already struggling."""
    entries = [_entry(n) for n in range(3)]
    for number, entry in enumerate(entries):
        entry["entry_id"] = f"g-{number}"

    result = adjudicate(
        entries,
        adjudicator=_FailingOn({"g-0", "g-1"}),
        cache=TriageCache(tmp_path / "t.jsonl"),
        max_calls=1,
    )

    assert result.calls == 1
    assert result.decisions["g-2"] is not None, "two failures used up the only call"
