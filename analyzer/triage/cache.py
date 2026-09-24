"""Ask once, pay once, and never spend past the cap."""

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from analyzer.triage.base import Adjudicator, Decision

# Spec section 12's hard spend guard. Exceeding it stops adjudication, marks
# the remainder uncertain and completes the run, rather than aborting: a run
# that aborted would publish nothing and look identical to a broken scanner,
# while one that silently kept spending is the failure the cap exists for.
MAX_CALLS_PER_RUN = 3_000


def cache_key(rule_id: str, evidence: str, context: str) -> str:
    """One question's identity.

    **A deliberate deviation from spec section 6.4**, which keys on
    `rule_id + evidence`. Since the adjudicator judges from the captured
    window rather than the evidence line alone, that key would hand two
    genuinely different findings one shared verdict - and the surrounding code
    is exactly what distinguishes a reachable call from a safe one.

    The free-text parts are hashed before being joined, the same guard
    `Finding.finding_id` uses. Evidence and context both come from a
    repository we do not control, so joining them raw would let a value
    containing the separator impersonate the boundary between fields, and two
    different questions would collapse to one cached answer.
    """
    parts = [hashlib.sha256(part.encode()).hexdigest() for part in (evidence, context)]
    return hashlib.sha256("|".join([rule_id, *parts]).encode()).hexdigest()


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


def adjudicate(
    entries: Sequence[Mapping[str, Any]],
    *,
    adjudicator: Adjudicator,
    cache: TriageCache,
    max_calls: int = MAX_CALLS_PER_RUN,
) -> dict[str, Decision | None]:
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
    spent = 0

    for entry in entries:
        key = cache_key(str(entry["rule_id"]), str(entry["evidence"]), str(entry["context"]))
        cached = cache.get(key)
        if cached is not None:
            results[str(entry["entry_id"])] = cached
            continue

        if spent >= max_calls:
            results[str(entry["entry_id"])] = None
            continue

        decision = adjudicator.decide(entry)
        spent += 1
        cache.put(key, decision)
        results[str(entry["entry_id"])] = decision

    return results
