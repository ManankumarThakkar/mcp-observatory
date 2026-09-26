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


# Statuses that mean "ask again" rather than "your request is wrong". 429 is a
# rate limit and the rest are upstream faults; every one of them resolves without
# the caller changing anything.
TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})

# Bounded, because an unbounded retry against a real outage is a run that never
# ends and, for a billable call, a bill that never stops. Four attempts covers a
# gateway blip without pretending it can outlast a genuine failure.
MAX_ATTEMPTS = 4

# The first wait, doubling each time. A fixed short delay against a rate limit
# re-triggers the rate limit, which is how a retry makes an outage worse.
FIRST_BACKOFF_SECONDS = 1.0


def is_transient(exc: BaseException) -> bool:
    """Whether a failure is worth asking again about.

    A missing status is transient: a dropped connection or a timeout carries no
    code at all, and over a run of several hundred calls it is the commonest
    interruption there is.

    Everything else is permanent by default. An unauthorised or malformed
    request will not fix itself, and retrying it wastes time, spends money where
    the call is billable, and delays the report of a fault someone has to act on.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in TRANSIENT_STATUSES
    return isinstance(exc, urllib.error.URLError | TimeoutError)


def _urlopen(request: urllib.request.Request) -> Mapping[str, Any]:
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        decoded: Mapping[str, Any] = json.load(response)
        return decoded


def post_json(
    url: str,
    body: Mapping[str, Any],
    *,
    send: Callable[[urllib.request.Request], Mapping[str, Any]] = _urlopen,
    sleep: Callable[[float], None] = time.sleep,
    token: str | None = None,
) -> Mapping[str, Any]:
    """Send one decision request, retrying the failures that are worth retrying.

    Separate from the adjudicator so that every test of the judging logic runs
    without a network, a key, or a prepaid balance. `send` and `sleep` are
    injected for the same reason one layer down: the retry behaviour itself needs
    testing, and a test that waited real seconds against a real service would be
    neither fast nor repeatable.

    Retries exist because of a measured failure, not a hypothetical one. A single
    502 on the first paid call aborted a 210-call experiment. Nothing was lost -
    answers are cached as they are made - but a run that cannot survive one bad
    gateway cannot be finished, and re-running by hand until it happens to get
    through is not a method.
    """
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {token if token is not None else bearer_token()}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    wait = FIRST_BACKOFF_SECONDS
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return send(request)
        except urllib.error.HTTPError as exc:
            if exc.code == 402:
                raise RuntimeError(
                    "the decision model's prepaid balance is empty; top it up before rerunning"
                ) from exc
            # Every other status carries the service's own explanation, and
            # discarding it turns a five-second diagnosis into a long one. A bare
            # "HTTP Error 400" cost exactly that once: the cause was an oversized
            # state, and the body said so.
            detail = exc.read().decode(errors="replace")[:300]
            if not is_transient(exc):
                raise RuntimeError(
                    f"the decision model returned HTTP {exc.code}: {detail}"
                ) from exc
            if attempt == MAX_ATTEMPTS:
                raise RuntimeError(
                    f"the decision model returned HTTP {exc.code} after "
                    f"{attempt} attempts: {detail}"
                ) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == MAX_ATTEMPTS:
                raise RuntimeError(
                    f"the decision model was unreachable after {attempt} attempts: {exc}"
                ) from exc

        sleep(wait)
        wait *= 2

    # Unreachable: the loop either returns or raises on its last attempt. Raising
    # rather than returning None, so a future edit that breaks that cannot hand a
    # caller a missing answer dressed as a real one.
    raise RuntimeError("retry loop ended without a decision")


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
