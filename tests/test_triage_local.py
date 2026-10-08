import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, ClassVar

import pytest

from analyzer.triage import frontier
from analyzer.triage.local import LocalAdjudicator, local_from_environment
from evals.harness import second_judge
from evals.harness.arms import ARMS, adjudicator_for
from tests.test_second_judge import _entry, _frozen

ENTRY: dict[str, Any] = {
    "entry_id": "g-0001",
    "rule_id": "SHELL-EXEC-UNSAFE",
    "language": "typescript",
    "context": "const branch = req.params.branch\nexec(`git log ${branch}`)",
    "flagged_offset": 1,
}

WEIGHTS = "mlx-community/Some-Model-oQ4e@0123456789abcdef0123456789abcdef01234567"
KEY = "sk-local-secret-value"


def _reply(content: str | None = '{"probability": 0.8}', finish: str = "stop", refusal: str | None = None) -> dict[str, Any]:
    return {"choices": [{"message": {"content": content, "refusal": refusal}, "finish_reason": finish}]}


class Recorder:
    """Stands in for the HTTP call, so no test needs a network or a model."""

    def __init__(self, reply: Mapping[str, Any]) -> None:
        self.reply = reply
        self.sent: list[tuple[str, Mapping[str, Any]]] = []

    def __call__(self, url: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        self.sent.append((url, body))
        return self.reply


def _judge(reply: Mapping[str, Any]) -> tuple[LocalAdjudicator, Recorder]:
    post = Recorder(reply)
    return LocalAdjudicator(post, base_url="http://studio.local:8000/v1", model="qwen-local", weights=WEIGHTS), post


def test_it_is_asked_exactly_what_the_frontier_judge_is_asked() -> None:
    # Two copies of a prompt drift, and the comparison would then be between
    # two questions rather than two models.
    judge, post = _judge(_reply())
    judge.decide(ENTRY)
    url, body = post.sent[0]
    assert url == "http://studio.local:8000/v1/chat/completions"
    assert body["messages"] == [{"role": "user", "content": frontier.build_prompt(ENTRY)}]
    assert body["response_format"]["json_schema"]["schema"] == frontier.RESPONSE_SCHEMA


def test_it_asks_the_named_model_at_temperature_zero() -> None:
    judge, post = _judge(_reply())
    judge.decide(ENTRY)
    body = post.sent[0][1]
    assert body["model"] == "qwen-local"
    assert body["temperature"] == 0


def test_the_probability_returned_is_the_one_recorded_and_costs_nothing() -> None:
    decision = _judge(_reply('{"probability": 0.8}'))[0].decide(ENTRY)
    assert decision.probability == 0.8
    assert decision.cost_usd == 0.0


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        (_reply(finish="length"), "truncated"),
        (_reply(content=None, refusal="I cannot help with that"), "refused"),
        (_reply('{"verdict": "real"}'), "no probability"),
        (_reply('{"probability": 85}'), "between 0 and 1"),
        (_reply("probably real"), "not JSON"),
    ],
)
def test_an_answer_that_is_not_a_probability_raises_rather_than_defaulting(reply: dict[str, Any], reason: str) -> None:
    # A defaulted answer would be scored as a measured one. A local model is
    # also likelier than a frontier one to answer 85 meaning 85%, which taken
    # literally is no probability at all.
    with pytest.raises(ValueError, match=reason):
        _judge(reply)[0].decide(ENTRY)


def test_the_identity_names_fixed_weights_and_the_sampling_and_never_the_key() -> None:
    identity = local_from_environment(
        {"OMLX_BASE_URL": "http://studio.local:8000/v1", "OMLX_MODEL": "qwen-local", "OMLX_WEIGHTS": WEIGHTS, "OMLX_API_KEY": KEY}
    ).identity
    assert identity["weights"] == WEIGHTS
    assert identity["model"] == "qwen-local"
    assert identity["temperature"] == 0
    assert KEY not in json.dumps(identity)


@pytest.mark.parametrize("missing", ["OMLX_BASE_URL", "OMLX_MODEL", "OMLX_WEIGHTS", "OMLX_API_KEY"])
def test_every_setting_is_required(missing: str) -> None:
    env = {"OMLX_BASE_URL": "http://studio.local:8000/v1", "OMLX_MODEL": "qwen-local", "OMLX_WEIGHTS": WEIGHTS, "OMLX_API_KEY": KEY}
    del env[missing]
    with pytest.raises(RuntimeError, match=missing):
        local_from_environment(env)


@pytest.mark.parametrize("weights", ["mlx-community/Some-Model", "mlx-community/Some-Model@", "@abc123"])
def test_weights_without_a_repository_and_revision_are_refused(weights: str) -> None:
    # "Fixed weights" with no named revision is a claim nobody can check.
    env = {"OMLX_BASE_URL": "http://studio.local:8000/v1", "OMLX_MODEL": "m", "OMLX_WEIGHTS": weights, "OMLX_API_KEY": KEY}
    with pytest.raises(RuntimeError, match="repository@revision"):
        local_from_environment(env)


def test_a_failed_request_never_carries_the_key_in_its_message() -> None:
    def failing(url: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        raise RuntimeError("the server returned HTTP 500: internal error")

    judge = LocalAdjudicator(failing, base_url="http://studio.local:8000/v1", model="m", weights=WEIGHTS)
    with pytest.raises(RuntimeError) as caught:
        judge.decide(ENTRY)
    assert KEY not in str(caught.value)
    assert KEY not in repr(judge)


def test_local_is_an_arm_and_unknown_arms_are_still_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in {"OMLX_BASE_URL": "http://studio.local:8000/v1", "OMLX_MODEL": "m", "OMLX_WEIGHTS": WEIGHTS, "OMLX_API_KEY": KEY}.items():
        monkeypatch.setenv(name, value)
    assert "local" in ARMS
    assert isinstance(adjudicator_for("local"), LocalAdjudicator)
    with pytest.raises(ValueError, match="oracle"):
        adjudicator_for("oracle")


class FixedLocal:
    name = "local"
    identity: ClassVar[dict[str, Any]] = {"model": "m", "weights": WEIGHTS, "temperature": 0}

    def decide(self, entry: Mapping[str, Any]) -> Any:
        from analyzer.triage.base import Decision

        return Decision(probability=0.6, cost_usd=0.0, latency_ms=1.0)


def test_a_run_records_which_weights_answered_beside_its_results(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, manifest = _frozen(tmp_path, [_entry(i, server=f"s/{i}") for i in range(3)])
    monkeypatch.setattr(second_judge, "adjudicator_for", lambda arm: FixedLocal())
    out = tmp_path / "arms"
    argv = ["--arm", "local", "--snapshot", str(snapshot), "--manifest", str(manifest), "--out", str(out)]
    second_judge.main([*argv, "--sample", "1"])
    second_judge.main([*argv, "--max-cost", "1"])
    second_judge.main([*argv, "--max-cost", "1", "--retest"])

    assert json.loads((out / "local.identity.json").read_text()) == FixedLocal.identity
    assert json.loads((out / "local.retest.identity.json").read_text()) == FixedLocal.identity


@pytest.mark.parametrize(
    "url",
    ["http://studio.local:8000/v1", "http://192.168.1.20:8000/v1", "http://10.0.0.5:8000/v1", "http://localhost:8000/v1", "http://127.0.0.1:8000/v1"],
)
def test_a_server_on_the_home_network_is_accepted(url: str) -> None:
    env = {"OMLX_BASE_URL": url, "OMLX_MODEL": "m", "OMLX_WEIGHTS": WEIGHTS, "OMLX_API_KEY": KEY}
    assert isinstance(local_from_environment(env), LocalAdjudicator)


@pytest.mark.parametrize(
    "url",
    ["https://api.example.com/v1", "http://8.8.8.8:8000/v1", "http://studio.local.example.com/v1", "ftp://studio.local/v1", "studio.local:8000"],
)
def test_a_server_outside_the_home_network_is_refused(url: str) -> None:
    # The frozen findings include withheld ones no maintainer has seen. A typo
    # in the address must not send them to a machine on the internet.
    env = {"OMLX_BASE_URL": url, "OMLX_MODEL": "m", "OMLX_WEIGHTS": WEIGHTS, "OMLX_API_KEY": KEY}
    with pytest.raises(RuntimeError, match="home network"):
        local_from_environment(env)
