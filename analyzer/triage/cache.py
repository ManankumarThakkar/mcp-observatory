"""Ask once, pay once, and never spend past the cap."""

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from analyzer.triage.base import Adjudicator, Decision, present

# Spec section 12's hard spend guard. Exceeding it stops adjudication, marks
# the remainder uncertain and completes the run, rather than aborting: a run
# that aborted would publish nothing and look identical to a broken scanner,
# while one that silently kept spending is the failure the cap exists for.
MAX_CALLS_PER_RUN = 3_000


def cache_key(arm: str, entry: Mapping[str, Any]) -> str:
    """One question's identity: who is being asked, and exactly what is sent.

    **The arm is part of the key.** Two adjudicators answering the same
    question is the entire point of the benchmark, so a key without the arm
    would let the second one run read the first's decisions and report
    identical precision - a plausible-looking result that was never measured,
    with nothing to indicate it.

    **A deliberate deviation from spec section 6.4**, which keys on
    `rule_id + evidence`. Evidence never reaches the model: the state is the
    rule's question, the language and the marked window. Keying on evidence
    would treat two identical questions as different and pay twice, while
    keying on rule and evidence alone would hand two genuinely different
    windows one shared verdict - and the surrounding code is exactly what
    distinguishes a reachable call from a safe one. The key is therefore over
    what is actually sent, which makes it provably right rather than
    approximately right.

    The free-text part is hashed before being joined, the same guard
    `Finding.finding_id` uses. The window comes from a repository we do not
    control, so joining it raw would let content containing the separator
    impersonate a field boundary and collapse two questions into one answer.
    """
    window = hashlib.sha256(present(entry).encode()).hexdigest()
    return hashlib.sha256(
        "|".join([arm, str(entry["rule_id"]), str(entry["language"]), window]).encode()
    ).hexdigest()


# Where adjudications already paid for are kept. Declared here rather than as a
# default buried in a command's arguments, because the pilot's own runner lived
# in an untracked file that is now gone: the path it used survived only as data
# on disk, and a second command guessing a different name would have re-bought
# every answer. The key already carries the arm, so one file serves every arm.
CACHE_PATH = Path(".cache/triage-jev.jsonl")


class TriageCache:
    """Adjudications already paid for, kept on disk.

    On disk rather than in memory because the whole point is that a nightly
    run costs nothing for findings that have not changed. A cache that lived
    only for one process would re-spend the entire bill every night, which is
    the failure it exists to prevent.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._entries: dict[str, Decision] | None = None

    def _load(self) -> dict[str, Decision]:
        if self._entries is not None:
            return self._entries

        entries: dict[str, Decision] = {}
        if self._path.exists():
            for number, line in enumerate(self._path.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    entries[record["key"]] = Decision(
                        probability=record["probability"],
                        cost_usd=record["cost_usd"],
                        latency_ms=record.get("latency_ms", 0.0),
                    )
                except (ValueError, KeyError, TypeError) as exc:
                    # Named rather than reset. Silently starting over would
                    # re-spend the entire cached bill with nothing to say why.
                    raise ValueError(
                        f"{self._path} is unreadable at line {number}: {exc}"
                    ) from exc
        self._entries = entries
        return entries

    def get(self, key: str) -> Decision | None:
        return self._load().get(key)

    def put(self, key: str, decision: Decision) -> None:
        """Append one answer, immediately.

        Appended per decision rather than written at the end, so a run
        interrupted two thousand calls in keeps what it already paid for.
        """
        self._load()[key] = decision
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "key": key,
                        "probability": decision.probability,
                        "cost_usd": decision.cost_usd,
                        "latency_ms": decision.latency_ms,
                    },
                    sort_keys=True,
                )
                + "\n"
            )


@dataclass(frozen=True)
class AdjudicationRun:
    """What one pass over the entries produced, and what it cost.

    Failures are carried beside the answers rather than raised, so one
    unreachable entry cannot discard a run that has already been paid for. They
    are kept apart from the entries the spend guard never reached because the two
    look identical downstream - both simply have no answer - while calling for
    different actions: one is re-run, the other needs the cap raised.

    Cost is measured rather than reconstructed afterwards from a price list,
    which is the same standard this project holds itself to about accuracy.
    """

    decisions: dict[str, Decision | None]
    failures: dict[str, str]
    calls: int
    cost_usd: float


def adjudicate(
    entries: Sequence[Mapping[str, Any]],
    *,
    adjudicator: Adjudicator,
    cache: TriageCache,
    max_calls: int = MAX_CALLS_PER_RUN,
) -> AdjudicationRun:
    """Judge every entry, paying only for the ones not already answered.

    `None` marks an entry the spend guard stopped short of. It is deliberately
    not a probability: a default would be indistinguishable from a real
    judgement downstream, and the gate must be able to tell "we decided this
    is unlikely" from "we never asked".

    The cap counts calls, not entries. Counting a cached hit against it would
    shrink what a nightly run adjudicates for no reason, and the shrink would
    grow as the cache filled - exactly backwards from what the cache is for.

    A failed adjudication is not cached. Caching it would make one outage
    permanent and that finding would never be judged again.
    """
    results: dict[str, Decision | None] = {}
    failures: dict[str, str] = {}
    spent = 0
    cost = 0.0

    for entry in entries:
        entry_id = str(entry["entry_id"])
        key = cache_key(adjudicator.name, entry)
        cached = cache.get(key)
        if cached is not None:
            results[entry_id] = cached
            continue

        if spent >= max_calls:
            results[entry_id] = None
            continue

        try:
            decision = adjudicator.decide(entry)
        except Exception as exc:  # noqa: BLE001
            # Isolated, not fatal. A single entry exhausting its retries used to
            # abort the whole run, and against a service answering in tens of
            # seconds that was near-certain over a few hundred calls. The
            # orchestrator already isolates one bad repository from a corpus run
            # for exactly this reason. Broad on purpose: any arm may raise
            # anything, and a run that survives one failure but not another kind
            # is a run whose completion depends on which service broke.
            #
            # Recorded rather than counted, because "the call failed" and "the
            # budget ran out" call for different actions and both otherwise
            # arrive as a missing answer.
            failures[entry_id] = f"{type(exc).__name__}: {exc}"
            results[entry_id] = None
            continue

        spent += 1
        cost += decision.cost_usd
        cache.put(key, decision)
        results[entry_id] = decision

    return AdjudicationRun(
        decisions=results, failures=failures, calls=spent, cost_usd=cost
    )
