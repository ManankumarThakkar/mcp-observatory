"""Adjudicate a finding with an open-weight model served on the home network."""

import ipaddress
import json
import time
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any

from analyzer.triage.base import Decision
from analyzer.triage.frontier import RESPONSE_SCHEMA, build_prompt
from analyzer.triage.jev import post_json

# A local model may reason before it answers, and a large one on a single
# machine is slow, so the decision model's 30-second timeout would fail calls
# that are merely thinking.
REQUEST_TIMEOUT_SECONDS = 600.0

# Room for reasoning before the one-number answer. A truncated answer raises
# rather than half-parsing, so the measured sample shows whether this is enough.
MAX_TOKENS = 4096

# Temperature 0 asks for the most likely answer. Determinism is still measured
# by the retest rather than assumed, as it was for the other judges.
TEMPERATURE = 0

SETTINGS = ("OMLX_BASE_URL", "OMLX_MODEL", "OMLX_WEIGHTS", "OMLX_API_KEY")

Post = Callable[[str, Mapping[str, Any]], Mapping[str, Any]]


class LocalAdjudicator:
    """The frontier judge's question, asked of a model whose weights are named.

    The HTTP call is injected, so every test runs without a network or a
    model, and the key lives only inside that call: an adjudicator that held it
    could print it in a repr or write it into its identity.
    """

    name = "local"

    def __init__(self, post: Post, *, base_url: str, model: str, weights: str) -> None:
        self._post = post
        self._url = f"{base_url.rstrip('/')}/chat/completions"
        self._model = model
        self.identity: dict[str, Any] = {
            "model": model,
            "weights": weights,
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
        }

    def __repr__(self) -> str:
        return f"LocalAdjudicator(model={self._model!r}, url={self._url!r})"

    def decide(self, entry: Mapping[str, Any]) -> Decision:
        started = time.monotonic()
        reply = self._post(
            self._url,
            {
                "model": self._model,
                "messages": [{"role": "user", "content": build_prompt(entry)}],
                "temperature": TEMPERATURE,
                "max_tokens": MAX_TOKENS,
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {"name": "verdict", "schema": RESPONSE_SCHEMA, "strict": True},
                },
            },
        )
        elapsed_ms = (time.monotonic() - started) * 1000

        entry_id = entry["entry_id"]
        choice = reply["choices"][0]
        # Checked before the content is touched: a refusal carries no answer and
        # a truncated reply carries half of one.
        if choice["message"].get("refusal"):
            raise ValueError(f"the model refused to answer for {entry_id}")
        if choice.get("finish_reason") == "length":
            raise ValueError(f"answer truncated by max_tokens for {entry_id}")

        text = choice["message"].get("content") or ""
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"answer for {entry_id} is not JSON: {text[:200]!r}") from exc
        if not isinstance(payload, dict) or "probability" not in payload:
            raise ValueError(f"answer for {entry_id} carried no probability: {text[:200]!r}")
        probability = float(payload["probability"])
        if not 0.0 <= probability <= 1.0:
            raise ValueError(f"answer for {entry_id} is not between 0 and 1: {probability}")

        return Decision(probability=probability, cost_usd=0.0, latency_ms=elapsed_ms)


def _urlopen(request: urllib.request.Request) -> Mapping[str, Any]:
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        decoded: Mapping[str, Any] = json.load(response)
        return decoded


def on_home_network(url: str) -> bool:
    """Whether a server address stays on this machine or the local network.

    The frozen findings include withheld ones, so this fails closed: a Bonjour
    name ending in .local, localhost, or a private or loopback address passes,
    and anything else, including a public name that merely contains ".local",
    is refused.
    """
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname or ""
    if parsed.scheme not in ("http", "https") or not host:
        return False
    if host == "localhost" or host.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback


def local_from_environment(env: Mapping[str, str]) -> LocalAdjudicator:
    """The local judge, configured from the environment, or a clear refusal.

    Weights must be named as repository@revision: the point of this judge is
    that anyone with the hardware can repeat the run, and a model name alone
    does not say which weights answered.
    """
    missing = [name for name in SETTINGS if not env.get(name)]
    if missing:
        raise RuntimeError(f"the local judge needs {', '.join(missing)} set")
    weights = env["OMLX_WEIGHTS"]
    repository, _, revision = weights.partition("@")
    if not repository or not revision:
        raise RuntimeError(f"OMLX_WEIGHTS must be repository@revision, got {weights!r}")
    if not on_home_network(env["OMLX_BASE_URL"]):
        raise RuntimeError(
            f"OMLX_BASE_URL must be on the home network (a .local name or a private address), "
            f"got {env['OMLX_BASE_URL']!r}"
        )
    token = env["OMLX_API_KEY"]

    def post(url: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        return post_json(url, body, send=_urlopen, token=token)

    return LocalAdjudicator(post, base_url=env["OMLX_BASE_URL"], model=env["OMLX_MODEL"], weights=weights)
