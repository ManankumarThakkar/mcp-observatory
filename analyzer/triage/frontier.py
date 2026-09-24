"""Adjudicate a finding with a frontier model, for comparison."""

import json
import time
from collections.abc import Mapping
from typing import Any

from analyzer.triage.base import Decision, present
from analyzer.triage.jev import build_question

# The current frontier model. Named once so the benchmark reports which model
# produced its figures, and so changing it is a visible diff rather than a
# scattered edit.
DEFAULT_MODEL = "claude-opus-5"

# Published per million tokens. Declared here so cost is computed from the
# reported token counts rather than guessed, and so the two halves of the
# arithmetic cannot drift apart in separate places.
INPUT_USD_PER_MTOK = 5.00
OUTPUT_USD_PER_MTOK = 25.00

# A classification answer is one number. Low rather than absent, because on
# this model disabling thinking has two documented failure modes - a tool call
# written into visible text, and leaked internal tags - and lowering effort
# gets the cost saving without either.
EFFORT = "low"
MAX_TOKENS = 256

# The answer's shape, fixed by the request rather than recovered from prose. A
# probability parsed out of free text is a judgement the model never actually
# expressed, which is exactly what DECISIONS.md D12 rejects.
RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "probability": {
            "type": "number",
            "description": (
                "Probability between 0 and 1 that this is a real security problem "
                "worth reporting to the maintainer."
            ),
        }
    },
    "required": ["probability"],
    "additionalProperties": False,
}


class FrontierAdjudicator:
    """The same question as the decision model, asked of a frontier model.

    The client is injected rather than constructed here, so every test of the
    judging logic runs with no key, no network and no spend.

    The wording comes from `build_question`, which both arms share. Two copies
    would drift, and the benchmark would then be comparing two questions
    rather than two judges - a difference it would report as if it were about
    the models.
    """

    name = "frontier"

    def __init__(self, client: Any, model: str = DEFAULT_MODEL) -> None:
        self._client = client
        self._model = model

    def decide(self, entry: Mapping[str, Any]) -> Decision:
        question = build_question(str(entry["rule_id"]))["real"]["instructions"]
        prompt = (
            f"{question}\n\n"
            f"Language: {entry['language']}\n\n"
            f"{present(entry)}\n\n"
            "Answer with your probability that this is a real problem."
        )

        started = time.monotonic()
        response = self._client.messages.create(
            model=self._model,
            max_tokens=MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
            output_config={"effort": EFFORT, "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA}},
        )
        elapsed_ms = (time.monotonic() - started) * 1000

        # Checked before the content is touched. A refusal carries no answer,
        # and a truncated response carries half of one: parsing either would
        # raise obscurely or, worse, yield a plausible-looking number.
        if response.stop_reason == "refusal":
            raise ValueError(f"the model refused to answer for {entry['entry_id']}")
        if response.stop_reason == "max_tokens":
            raise ValueError(f"answer truncated by max_tokens for {entry['entry_id']}")

        text = next((block.text for block in response.content if block.type == "text"), "")
        payload = json.loads(text)
        if "probability" not in payload:
            # Never default. A degraded run would otherwise mark findings
            # false positives and be published as a measured result.
            raise ValueError(f"response carried no probability: {text!r}")

        usage = response.usage
        cost = (
            usage.input_tokens * INPUT_USD_PER_MTOK
            + usage.output_tokens * OUTPUT_USD_PER_MTOK
        ) / 1_000_000

        return Decision(
            probability=float(payload["probability"]),
            cost_usd=cost,
            latency_ms=elapsed_ms,
        )
