"""Adjudicate a finding with a calibrated yes/no from a decision model."""

import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from analyzer.rules import ALL_RULES
from analyzer.triage.base import Decision, present

JEV_ENDPOINT = "https://jevtypesafeai.com/api/v1/decide"

# Read from the environment rather than a flag, so it stays out of shell
# history, and never logged. The nightly job supplies it as a secret.
TOKEN_VARIABLE = "JEV_API_KEY"

REQUEST_TIMEOUT_SECONDS = 30.0

# The single question asked about every finding. A `noul` returns one
# calibrated probability of one proposition, which is exactly what a published
# threshold applies to. A `choice` would return a distribution over labels we
# invented, and recovering a probability from that is the parsing
# `DECISIONS.md` D12 exists to avoid.
ANSWER_KEY = "real"

PostFn = Callable[[str, Mapping[str, Any]], Mapping[str, Any]]

# Each rule's question is built from the rule's own title and description, so
# the model is asked the same claim the published finding makes and the same
# claim the human labeller was shown. Two copies of that wording would drift,
# and the drift would be invisible: the benchmark would keep reporting a
# precision for a question nobody was asking any more.
_RULE_TEXT = {rule.rule_id: (rule.title, rule.description) for rule in ALL_RULES}


def build_question(rule_id: str) -> dict[str, Any]:
    """The question this rule's findings are judged by.

    Raises for an unknown rule rather than falling back to something generic.
    A rule added later must fail loudly here; adjudicating it with wording
    written for a different rule produces a precision figure for the wrong
    proposition, and nothing downstream would say so.

    The wording matches `evals/golden/LABELLING.md`: whether this is a real
    problem worth reporting, not whether the pattern is present. The human was
    asked that question, so asking the model a different one would compare two
    questions rather than two judges.
    """
    title, description = _RULE_TEXT[rule_id]
    return {
        ANSWER_KEY: {
            "type": "noul",
            "instructions": (
                f"The marked line below was flagged as: {title}. {description} "
                "Judging only from this code, is this a real security problem "
                "worth reporting to the maintainer, rather than a safe, fixed "
                "or unreachable use of the same pattern?"
            ),
        }
    }


def post_json(url: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
    """Send one decision request, with the key read at call time.

    Separate from the adjudicator so that every test of the judging logic runs
    without a network, a key, or a prepaid balance.
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {bearer_token()}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            decoded: Mapping[str, Any] = json.load(response)
            return decoded
    except urllib.error.HTTPError as exc:
        if exc.code == 402:
            # Named rather than surfaced as a bare 402, because a run of three
            # hundred that stops a third of the way through with "HTTP error"
            # is a diagnosis somebody has to go and make.
            raise RuntimeError(
                "the decision model's prepaid balance is empty; top it up before rerunning"
            ) from exc
        raise


class JevAdjudicator:
    """A calibrated probability per finding, and what it cost to get.

    `post` is injected for the reason every network boundary here is: a test
    of the adjudication logic should not need a network or a balance.
    """

    name = "jev"

    def __init__(self, post: PostFn) -> None:
        self._post = post

    def decide(self, entry: Mapping[str, Any]) -> Decision:
        """Ask one question about one finding.

        The state is the language and the marked window, and nothing else. It
        is exactly what the human labeller saw, which is what makes the
        comparison a comparison of judgement; adding the server name or file
        path would both widen what the model knows beyond the label and send
        an identifier to a third party for no benefit.
        """
        body = {
            "state": f"Language: {entry['language']}\n\n{present(entry)}",
            "questions": build_question(str(entry["rule_id"])),
        }

        started = time.monotonic()
        payload = self._post(JEV_ENDPOINT, body)
        elapsed_ms = (time.monotonic() - started) * 1000

        answer = payload.get("answers", {}).get(ANSWER_KEY, {})
        if "noul" not in answer:
            # Never default. A missing answer during an outage would become
            # 0.0, marking every finding a false positive, and the run would
            # complete looking entirely successful.
            raise ValueError(f"response carried no noul answer: {payload}")

        # A missing usage block reports zero rather than an estimate. The
        # benchmark publishes cost per decision, and a guessed figure there is
        # the same failure as a guessed accuracy figure.
        usage = payload.get("usage", {})
        return Decision(
            probability=float(answer["noul"]),
            cost_usd=float(usage.get("cost_usd", 0.0)),
            latency_ms=elapsed_ms,
        )


def bearer_token() -> str:
    """The API key, or a clear refusal.

    Checked when it is needed rather than at import, so the rest of the triage
    package stays importable without a key - the baseline arm needs none.
    """
    token = os.environ.get(TOKEN_VARIABLE, "")
    if not token:
        raise RuntimeError(f"{TOKEN_VARIABLE} is not set; the decision model needs a key")
    return token
