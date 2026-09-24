from dataclasses import dataclass, field
from typing import Any

import pytest

from analyzer.triage.frontier import (
    DEFAULT_MODEL,
    INPUT_USD_PER_MTOK,
    OUTPUT_USD_PER_MTOK,
    FrontierAdjudicator,
)

ENTRY: dict[str, Any] = {
    "entry_id": "g-0001",
    "rule_id": "SHELL-EXEC-UNSAFE",
    "language": "typescript",
    "context": "const branch = req.params.branch\nexec(`git log ${branch}`)",
    "flagged_offset": 1,
}


@dataclass
class _Block:
    text: str
    type: str = "text"


@dataclass
class _Usage:
    input_tokens: int = 100
    output_tokens: int = 10


@dataclass
class _Response:
    content: list[_Block]
    usage: _Usage = field(default_factory=_Usage)
    stop_reason: str = "end_turn"
    stop_details: Any = None


class _FakeMessages:
    def __init__(self, response: _Response) -> None:
        self._response = response
        self.sent: dict[str, Any] = {}

    def create(self, **kwargs: Any) -> _Response:
        self.sent = kwargs
        return self._response


class _FakeClient:
    def __init__(self, response: _Response) -> None:
        self.messages = _FakeMessages(response)


def _client(probability: float = 0.88, **usage: int) -> _FakeClient:
    return _FakeClient(
        _Response(content=[_Block(f'{{"probability": {probability}}}')], usage=_Usage(**usage))
    )


def test_the_probability_the_model_returned_is_the_one_recorded() -> None:
    assert FrontierAdjudicator(_client(0.88)).decide(ENTRY).probability == 0.88


def test_cost_is_computed_from_the_reported_token_counts() -> None:
    """Measured from usage, not assumed. The benchmark publishes cost per
    decision beside precision, and an assumed figure there is the same failure
    as an assumed accuracy figure."""
    client = _client(0.5, input_tokens=1_000_000, output_tokens=1_000_000)

    cost = FrontierAdjudicator(client).decide(ENTRY).cost_usd

    assert cost == pytest.approx(INPUT_USD_PER_MTOK + OUTPUT_USD_PER_MTOK)


def test_both_arms_are_asked_the_same_question() -> None:
    """Otherwise the benchmark compares two questions rather than two models,
    and the difference it reports is unattributable to either."""
    from analyzer.triage.jev import build_question

    client = _client()
    FrontierAdjudicator(client).decide(ENTRY)

    prompt = str(client.messages.sent["messages"])
    assert build_question("SHELL-EXEC-UNSAFE")["real"]["instructions"] in prompt


def test_the_window_reaches_the_model_with_the_flagged_line_marked() -> None:
    """The labeller saw it marked, and so does the other arm."""
    client = _client()
    FrontierAdjudicator(client).decide(ENTRY)

    assert "> exec(`git log ${branch}`)" in str(client.messages.sent["messages"])


def test_the_server_name_never_reaches_the_model() -> None:
    client = _client()
    FrontierAdjudicator(client).decide({**ENTRY, "server_id": "acme/notes", "file": "src/run.ts"})

    sent = str(client.messages.sent)
    assert "acme/notes" not in sent
    assert "src/run.ts" not in sent


def test_the_response_is_constrained_to_a_schema_rather_than_parsed_from_prose() -> None:
    """A probability recovered by parsing free text is a judgement the model
    never actually expressed, which is the failure D12 exists to avoid."""
    client = _client()
    FrontierAdjudicator(client).decide(ENTRY)

    fmt = client.messages.sent["output_config"]["format"]
    assert fmt["type"] == "json_schema"
    assert fmt["schema"]["required"] == ["probability"]
    assert fmt["schema"]["additionalProperties"] is False


def test_the_model_is_the_current_frontier_one() -> None:
    client = _client()
    FrontierAdjudicator(client).decide(ENTRY)

    assert client.messages.sent["model"] == DEFAULT_MODEL == "claude-opus-5"


def test_a_refusal_raises_rather_than_being_read_as_content() -> None:
    """stop_reason must be checked before content is touched. A refusal
    carries no probability, and reading content anyway would either crash
    obscurely or invent a number."""
    response = _Response(content=[], stop_reason="refusal")

    with pytest.raises(ValueError, match="refus"):
        FrontierAdjudicator(_FakeClient(response)).decide(ENTRY)


def test_a_truncated_response_raises_rather_than_half_parsing() -> None:
    """max_tokens on a classification means the JSON is cut off. Parsing what
    arrived would produce either an error or, worse, a valid-looking number."""
    response = _Response(content=[_Block('{"probability": 0.8')], stop_reason="max_tokens")

    with pytest.raises(ValueError, match="max_tokens"):
        FrontierAdjudicator(_FakeClient(response)).decide(ENTRY)


def test_a_missing_probability_field_raises_rather_than_defaulting() -> None:
    """Defaulting would mark findings false positives during a degraded run
    and the benchmark would report it as a measured result."""
    response = _Response(content=[_Block('{"verdict": "yes"}')])

    with pytest.raises(ValueError, match="probability"):
        FrontierAdjudicator(_FakeClient(response)).decide(ENTRY)


def test_a_probability_outside_the_range_is_refused_at_the_boundary() -> None:
    with pytest.raises(ValueError, match="probability"):
        FrontierAdjudicator(_client(1.7)).decide(ENTRY)
