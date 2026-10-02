"""Merging tonight's findings into the history, so a trend exists at all."""

import json
import re
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# A full git object name, either case. Git accepts both and some tools emit
# uppercase.
COMMIT_SHA = re.compile(r"\A[0-9a-fA-F]{40}\Z")

Record = dict[str, Any]


def utc_stamp(moment: datetime) -> str:
    """Render an instant the way every record and document here writes one.

    UTC, to the second. Microseconds would make a committed file churn on
    sub-second noise, and a naive local time would make two machines disagree
    about when the same scan ran. Defined once because the coverage document
    and the findings history must not drift into two formats.
    """
    return moment.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")



def _require_real_commit(record: Record) -> None:
    """Refuse a record that cannot name the commit it was found at.

    `--path` scans a working copy and labels findings `commit_sha="local"`.
    Because `finding_id` excludes commit_sha, such a record shares an identity
    with a genuine finding for the same server and rule, so merging one would
    overwrite real history with a commit that does not exist and cannot be
    checked.

    One check at the boundary beats a convention every producer has to
    remember, and this is the boundary: nothing reaches the published history
    except through here.
    """
    sha = record.get("commit_sha", "")
    if not isinstance(sha, str) or not COMMIT_SHA.match(sha):
        raise ValueError(
            f"commit_sha must be 40 hexadecimal characters to enter the history; "
            f"got {sha!r} for finding {record.get('finding_id', '?')!r}"
        )


def merge_findings(
    previous: Sequence[Record], current: Sequence[Record], *, now: str
) -> list[Record]:
    """Fold tonight's findings into the history and return the whole of it.

    A finding seen again keeps its `first_seen` and advances its `last_seen`,
    which is what turns a pile of nightly snapshots into a time series.
    `finding_id` is deterministic and excludes commit_sha for exactly this
    reason, so the same issue across two runs is one record.

    **A finding absent from tonight's run is kept, not deleted.** This is spec
    section 9's partial-run tolerance and the most important property here. A
    run covering 60% of the corpus updates 60% and leaves the rest alone: if a
    rate limit stops the crawler halfway, the missing 40% are unknown tonight,
    not resolved tonight, and deleting them would rewrite history and make the
    published trend a lie.

    The cost is that a genuinely fixed finding lingers with a stale
    `last_seen`. That is the right trade, because a stale timestamp reads as
    "not seen since August" while a deleted record is indistinguishable from
    one that never existed. Any resolved view belongs in the dashboard,
    derived from the age of `last_seen` rather than from deletion here.
    """
    merged: dict[str, Record] = {}

    for record in previous:
        finding_id = record["finding_id"]
        # A record written before these fields existed still counts as seen;
        # dropping it to avoid a missing key would lose real history.
        merged[finding_id] = {
            **record,
            "first_seen": record.get("first_seen") or now,
            "last_seen": record.get("last_seen") or now,
        }

    for record in current:
        _require_real_commit(record)
        finding_id = record["finding_id"]
        existing = merged.get(finding_id)
        merged[finding_id] = {
            **record,
            # Kept from the existing record: how long this has been true is
            # the one thing tonight's run cannot know.
            "first_seen": existing["first_seen"] if existing else now,
            "last_seen": now,
        }
        if existing and existing.get("previous_ids"):
            merged[finding_id]["previous_ids"] = list(existing["previous_ids"])

    _carry_moved(merged, now=now)

    # Sorted by identity, so two runs that found the same things produce the
    # same file and a diff in the repository always means the findings moved.
    return [merged[finding_id] for finding_id in sorted(merged)]


def _where_and_what(record: Record) -> tuple[str, str, str, str]:
    return (
        str(record["server_id"]),
        str(record["rule_id"]),
        str(record["location"]["file"]),
        str(record["evidence"]),
    )


def _carry_moved(merged: dict[str, Record], *, now: str) -> None:
    """Treat a finding whose code only moved line as the same finding.

    The line is part of `finding_id`, so an edit anywhere above a finding gives
    it a new id. Measured on 2026-10-02, all 41 findings that vanished between
    runs had reappeared at another line of the same file with identical
    evidence. Taken at face value, that resets how long a finding has existed
    and orphans any notice sent about it.

    Records not seen tonight are paired with records first seen tonight that
    have the same server, rule, file and evidence, when the same number vanished
    as arrived, in line order: inserted code shifts repeated findings down
    together. Pairing only unique evidence matched 5 of those 41, because one
    file held 36 with identical evidence. Unequal counts are left alone: separate
    records are the safe outcome, since a finding no notice names is withheld.
    The id is not changed to drop the line, because every id already issued,
    including the frozen study's, would stop matching.
    """
    vanished: dict[tuple[str, str, str, str], list[str]] = {}
    arrived: dict[tuple[str, str, str, str], list[str]] = {}
    for finding_id, record in merged.items():
        if record["last_seen"] != now:
            vanished.setdefault(_where_and_what(record), []).append(finding_id)
        elif record["first_seen"] == now:
            arrived.setdefault(_where_and_what(record), []).append(finding_id)

    def by_line(finding_id: str) -> int:
        return int(merged[finding_id]["location"]["line"])

    for key, old_ids in vanished.items():
        new_ids = arrived.get(key, [])
        if len(old_ids) != len(new_ids):
            continue
        for old_id, new_id in zip(sorted(old_ids, key=by_line), sorted(new_ids, key=by_line), strict=True):
            old = merged.pop(old_id)
            new = merged[new_id]
            new["first_seen"] = old["first_seen"]
            new["previous_ids"] = [*old.get("previous_ids", []), old["finding_id"]]


def load_previous(path: Path) -> list[Record]:
    """Read the history, or an empty one if there is none yet.

    A missing file is the first run rather than an error, so the pipeline
    needs no special case for it.

    A malformed line stops the run. Skipping it would silently shorten the
    published history, and a trend with an invisible hole in it is worse than
    a run that fails where somebody can see it.
    """
    if not path.exists():
        return []

    records: list[Record] = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path} is corrupt at line {number}: {exc}") from exc
    return records


def seen_in(records: Iterable[Record], stamp: str) -> list[Record]:
    """The records one scan produced, out of a history that holds every scan.

    Every published finding and every count comes from here. The history keeps
    older records because a disclosure window outlives a night, but counting
    them as current is how a republication once reported 1,301 findings for a
    scan that had produced 1,122.
    """
    return [record for record in records if record.get("last_seen") == stamp]


def write_findings(path: Path, records: Iterable[Record]) -> None:
    """Write the history as one JSON object per line.

    JSON Lines rather than one array, so appending a night's results is a
    readable diff rather than a rewrite of the whole document, and so a
    partial read is still a list of complete records.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
