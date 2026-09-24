"""The one place a published benchmark entry is written."""

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from analyzer.models import Finding
from analyzer.report.gate import PUBLISHABLE_STATES, DisclosureRecord, disclosure_state

# Everything a reader needs to form and score a verdict, and nothing that says
# whose code it is. An allowlist rather than a list of things to strip: a
# strip-list needs updating every time the local entry gains a field, and it
# fails open when it is out of date, which is precisely when a new field
# appears.
#
# `finding_id` is deliberately absent. It hashes server_id, rule, path, line
# and evidence; the server index and the rules are public and the context is
# published here, so the hash can be recomputed for every candidate server and
# matched back. A hash over public inputs identifies rather than anonymises.
#
# The file path is absent for a weaker version of the same reason: a path like
# `src/tools/watch-window.ts` is distinctive enough to search for, and it is
# not needed to judge a window that is already in the entry.
#
# `flagged_offset` is present because without it the entry is ambiguous. The
# window is twenty-five lines and the flagged line is not reliably the middle
# one: near the top of a file the window is clamped and the centre moves.
PUBLISHED_FIELDS: tuple[str, ...] = (
    "entry_id",
    "rule_id",
    "severity",
    "confidence",
    "language",
    "context",
    "flagged_offset",
    "label",
)


def redact(entry: Mapping[str, Any]) -> dict[str, Any]:
    """The publishable form of one golden-set entry.

    Refuses an entry missing any published field rather than emitting a
    partial one. A benchmark entry with no label is an unanswered question in
    a file that claims to hold answers, and a reader scoring against it would
    count it as a disagreement with whatever they predicted.
    """
    missing = [field for field in PUBLISHED_FIELDS if field not in entry]
    if missing:
        raise ValueError(f"entry cannot be published without {', '.join(missing)}")
    return {field: entry[field] for field in PUBLISHED_FIELDS}


def publish(
    entries: Sequence[Mapping[str, Any]],
    *,
    findings: Mapping[str, Finding],
    disclosure_records: Mapping[str, DisclosureRecord],
    now: datetime,
) -> list[dict[str, Any]]:
    """Every entry that may be published, redacted.

    Two controls, not one, because redaction alone is not enough for a finding
    inside its disclosure window. Removing the server name removes the easy
    path back to it; the context is verbatim source, and a search engine that
    has indexed the repository will find it from a distinctive line. Measured
    on 2026-09-24 against GitHub's code search API, a distinctive line from
    one sampled repository returned nothing while a control query returned
    52,864 matches, so that repository is simply not indexed - which makes
    re-identification unreliable rather than impossible, and unreliable is not
    a control. For a high or critical finding the difference is the entire
    reason the ninety-day window exists.

    So the window is enforced here too, reusing the report gate's definition
    rather than restating it. Two answers to "is this withheld" would drift,
    and the drift would surface as a benchmark quietly disclosing what the
    dashboard was still holding back. Opt-out is honoured unconditionally, as
    spec section 11 requires: a benchmark is still publication.

    The consequence is that the benchmark starts with the findings that were
    never withheld and grows as windows close, rather than either shipping
    everything immediately or waiting ninety days to ship at all.
    """
    publishable: list[dict[str, Any]] = []
    for entry in entries:
        entry_id = entry["entry_id"]
        if entry_id not in findings:
            # Without the finding there is no severity and no server, so the
            # entry cannot be gated. Publishing it anyway would be exactly the
            # bypass this module exists to prevent.
            raise KeyError(f"no finding for entry {entry_id}; it cannot be gated")

        finding = findings[entry_id]
        state = disclosure_state(
            finding, disclosure_records.get(finding.server_id), now=now
        )
        if state in PUBLISHABLE_STATES:
            publishable.append(redact(entry))
    return publishable
