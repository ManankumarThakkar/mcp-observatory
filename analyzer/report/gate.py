"""The disclosure gate: what may be published, enforced in code."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Literal, get_args

from analyzer.models import Finding

# SECURITY.md: a finding's window opens on the date its maintainer is told
# about that finding, and it may be published once the window closes.
DISCLOSURE_WINDOW = timedelta(days=90)

# Severities that wait. Anything below this publishes immediately, because
# withholding a low-severity finding buys a maintainer nothing and costs the
# index most of what it reports.
GATED_SEVERITIES = frozenset({"critical", "high"})

# "withdrawn": a serious finding shown to be wrong; never published.
# "retracted": a finding already published, then withdrawn as our error; it stays
# visible, marked, because an honest correction is what this project publishes.
DisclosureState = Literal[
    "opted_out", "withheld", "disclosed", "published", "withdrawn", "retracted"
]

# Every state, so a caller reading counts never has to guard a missing key.
ALL_STATES: tuple[DisclosureState, ...] = get_args(DisclosureState)

# The two states whose findings may be written in a publishable form. Named
# rather than inlined so the one place that decides publication is greppable,
# and so adding a state cannot accidentally make it publishable by default.
PUBLISHABLE_STATES = frozenset({"disclosed", "published", "retracted"})


@dataclass(frozen=True)
class DisclosureRecord:
    """What is known about contact with one server's maintainer.

    `notified` maps a finding id to the date of the first notice that named
    it. The window belongs to the finding, not the server: one date per server
    would start the clock for every serious finding on it, including ones the
    notice never mentioned - the unverified findings that are never published
    individually - and ones first seen after the notice was sent. A finding
    absent from `notified` has no window at all.
    """

    server_id: str
    notified: Mapping[str, datetime] = field(default_factory=dict)
    opted_out: bool = False
    # Findings withdrawn: disputed and shown wrong, or ours to retract.
    withdrawn: frozenset[str] = frozenset()
    # A later end agreed with the maintainer, per finding. It can only lengthen
    # a window, never shorten one.
    extended: Mapping[str, datetime] = field(default_factory=dict)


def _require_aware(moment: datetime, field: str) -> None:
    """Refuse a naive timestamp at the boundary rather than deep in a run.

    Comparing a naive datetime to an aware one raises TypeError wherever the
    comparison happens, which on a nightly publish is a long way from the bad
    value. Failing here names the field instead.
    """
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError(f"{field} must carry a timezone; got a naive datetime {moment!r}")


def disclosure_state(
    finding: Finding, record: DisclosureRecord | None, *, now: datetime
) -> DisclosureState:
    """Which state this finding is in.

    Spec section 11 requires this to be code rather than convention: a finding
    cannot reach a publishable state without passing through here.

    Every uncertain path resolves to withheld. A missing record, a
    notification that never happened, a timestamp from the future: none of
    them are evidence that a maintainer was told, and publishing on the
    strength of missing data is the one mistake this gate exists to prevent.
    """
    _require_aware(now, "now")

    # First and unconditionally. Spec section 14 makes opt-out unconditional,
    # and a check placed after any other would make it conditional on that
    # other thing.
    if record is not None and record.opted_out:
        return "opted_out"

    gated = finding.severity in GATED_SEVERITIES
    if record is not None and finding.finding_id in record.withdrawn:
        return "withdrawn" if gated else "retracted"

    if not gated:
        return "published"

    notified_at = record.notified.get(finding.finding_id) if record is not None else None
    if notified_at is None:
        return "withheld"

    _require_aware(notified_at, "notified_at")
    window_ends = notified_at + DISCLOSURE_WINDOW
    extension = record.extended.get(finding.finding_id) if record is not None else None
    if extension is not None:
        _require_aware(extension, "extended")
        window_ends = max(window_ends, extension)

    # Strictly greater than, so the boundary is not a publication. An
    # off-by-one here publishes a day early, which is the only direction this
    # gate must never be wrong in. A future timestamp fails the same test.
    if now > window_ends:
        return "disclosed"
    return "withheld"


def split_for_publication(
    findings: Sequence[Finding],
    records: Mapping[str, DisclosureRecord],
    *,
    now: datetime,
) -> tuple[list[Finding], dict[str, int]]:
    """Separate what may be published from what may not, and count both.

    The counts are the point of returning a pair. Spec section 11 publishes
    aggregate statistics immediately, so the dashboard can say "41 critical
    findings withheld pending disclosure" without naming a single server.

    Input order is preserved, so a document built from this is stable across
    runs that found the same things.
    """
    published: list[Finding] = []
    counts: dict[str, int] = dict.fromkeys(ALL_STATES, 0)

    for finding in findings:
        state = disclosure_state(finding, records.get(finding.server_id), now=now)
        counts[state] += 1
        if state in PUBLISHABLE_STATES:
            published.append(finding)

    return published, counts
