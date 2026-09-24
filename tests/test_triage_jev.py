from collections.abc import Mapping
from typing import Any

import pytest

from analyzer.triage.jev import JevAdjudicator, build_question

ENTRY: dict[str, Any] = {
    "entry_id": "g-0001",
    "rule_id": "SHELL-EXEC-UNSAFE",
    "language": "typescript",
    "context": "const branch = req.params.branch\nexec(`git log ${branch}`)",
    "flagged_offset": 1,
}

RESPONSE: dict[str, Any] = {
    "answers": {"real": {"type": "noul", "noul": 0.93}},
    "usage": {"input_tokens": 240, "cost_usd": 0.0001, "credits_remaining_usd": 4.5},
}


def test_the_calibrated_probability_is_carried_through_unchanged() -> None:
    """The number is published with a threshold beside it. Rounding, clamping
    or rescaling it here would make the published threshold describe something
    other than what the model returned."""
    assert JevAdjudicator(post=lambda url, body: RESPONSE).decide(ENTRY).probability == 0.93


def test_the_cost_is_the_one_the_service_reported() -> None:
    """Cost per decision is published beside precision. Deriving it from a
    price list would be an estimate presented as a measurement, which is the
    thing this project refuses to do about accuracy."""
    assert JevAdjudicator(post=lambda url, body: RESPONSE).decide(ENTRY).cost_usd == 0.0001


def test_the_state_carries_the_window_with_the_flagged_line_marked() -> None:
    """The labeller sees the flagged line marked. A model that did not would
    be answering a different question, and the benchmark would report a
    difference in presentation as a difference in judgement."""
    sent: dict[str, Any] = {}

    def post(url: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        sent.update(body)
        return RESPONSE

    JevAdjudicator(post=post).decide(ENTRY)

    assert "> exec(`git log ${branch}`)" in str(sent["state"])
    assert "  const branch = req.params.branch" in str(sent["state"])


def test_the_server_name_never_reaches_the_service() -> None:
    """It is not in the window the labeller saw, so including it would both
    widen what the model knows beyond the label and send an identifier to a
    third party for no benefit."""
    sent: dict[str, Any] = {}

    def post(url: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        sent.update(body)
        return RESPONSE

    JevAdjudicator(post=post).decide({**ENTRY, "server_id": "acme/notes", "file": "src/run.ts"})

    assert "acme/notes" not in str(sent)
    assert "src/run.ts" not in str(sent)


def test_each_rule_asks_its_own_question() -> None:
    """A wildcard origin and a planted instruction are different propositions
    with different right answers, so one generic question would be measuring
    the wrong thing for at least one rule."""
    shell = build_question("SHELL-EXEC-UNSAFE")["real"]["instructions"]
    desc = build_question("TOOL-DESC-INJECTION")["real"]["instructions"]

    assert shell != desc


def test_the_question_is_the_claim_the_published_finding_makes() -> None:
    """Read from the rule rather than restated here. Two copies would drift,
    and the benchmark would report a precision for a question nobody asks."""
    from analyzer.rules import ALL_RULES

    rule = next(r for r in ALL_RULES if r.rule_id == "SHELL-EXEC-UNSAFE")
    instructions = build_question("SHELL-EXEC-UNSAFE")["real"]["instructions"]

    assert rule.title in instructions


def test_a_question_for_an_unknown_rule_is_refused() -> None:
    """A rule added later must fail loudly rather than be adjudicated by
    wording written for a different one."""
    with pytest.raises(KeyError, match="NO-SUCH-RULE"):
        build_question("NO-SUCH-RULE")


def test_the_question_is_a_noul_because_a_threshold_is_applied_to_it() -> None:
    """A choice would return a distribution over labels we invented, and
    recovering a probability from it is the parsing D12 exists to avoid."""
    assert build_question("SHELL-EXEC-UNSAFE")["real"]["type"] == "noul"


def test_a_response_missing_the_answer_is_an_error_not_a_default() -> None:
    """Defaulting to 0.0 would mark every finding a false positive during an
    outage, and the run would complete looking entirely successful."""
    adjudicator = JevAdjudicator(post=lambda url, body: {"usage": {"cost_usd": 0.0}})

    with pytest.raises(ValueError, match="noul"):
        adjudicator.decide(ENTRY)


def test_a_probability_outside_the_range_is_refused_at_the_boundary() -> None:
    """Decision validates it; this proves the adjudicator does not bypass
    Decision by building something else."""
    bad = {"answers": {"real": {"type": "noul", "noul": 1.4}}, "usage": {"cost_usd": 0.0}}

    with pytest.raises(ValueError, match="probability"):
        JevAdjudicator(post=lambda url, body: bad).decide(ENTRY)


def test_a_missing_usage_block_does_not_invent_a_cost() -> None:
    """Zero is the honest answer when the service did not say. A guessed
    figure would be published as a measured one."""
    thin = {"answers": {"real": {"type": "noul", "noul": 0.5}}}

    assert JevAdjudicator(post=lambda url, body: thin).decide(ENTRY).cost_usd == 0.0
