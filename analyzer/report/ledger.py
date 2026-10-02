"""The disclosure ledger: which findings were reported to which maintainer, and when.

It is the only source of the dates the gate opens windows from, so every rule
about what a notice may record lives here, next to the record itself.
"""

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, get_args

from analyzer.report.gate import DisclosureRecord
from analyzer.report.merge import utc_stamp

Channel = Literal["private_advisory", "security_contact", "contact_request"]

# A public issue asking for a contact describes no finding, so it tells no
# maintainer anything and cannot start a window. Only a private notice can.
WINDOW_CHANNELS: frozenset[Channel] = frozenset({"private_advisory", "security_contact"})


class LedgerRefused(ValueError):
    """A notice that cannot be recorded as it stands."""


def _aware(moment: datetime, name: str) -> datetime:
    if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
        raise ValueError(f"{name} must carry a timezone; got {moment!r}")
    return moment


def _parse(stamp: str | None) -> datetime | None:
    return None if stamp is None else _aware(datetime.fromisoformat(stamp), "a ledger date")


@dataclass(frozen=True)
class Notice:
    """One notice sent to one maintainer, naming exactly the findings it described."""

    server_id: str
    finding_ids: tuple[str, ...]
    channel: Channel
    notified_at: datetime
    reference: str
    verified_by: str
    acknowledged_at: datetime | None = None
    fixed_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.channel not in get_args(Channel):
            raise ValueError(f"channel must be one of {', '.join(get_args(Channel))}")
        _aware(self.notified_at, "notified_at")
        for name in ("acknowledged_at", "fixed_at"):
            moment = getattr(self, name)
            if moment is not None:
                _aware(moment, name)

    @property
    def notice_id(self) -> str:
        return f"{self.server_id}@{utc_stamp(self.notified_at)}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "notice",
            "server_id": self.server_id,
            "finding_ids": list(self.finding_ids),
            "channel": self.channel,
            "notified_at": utc_stamp(self.notified_at),
            "reference": self.reference,
            "verified_by": self.verified_by,
            "acknowledged_at": None if self.acknowledged_at is None else utc_stamp(self.acknowledged_at),
            "fixed_at": None if self.fixed_at is None else utc_stamp(self.fixed_at),
        }


@dataclass(frozen=True)
class OptOut:
    """A maintainer asked to be excluded. Honoured without argument (spec section 14)."""

    server_id: str
    requested_at: datetime

    def __post_init__(self) -> None:
        _aware(self.requested_at, "requested_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "opt_out",
            "server_id": self.server_id,
            "requested_at": utc_stamp(self.requested_at),
        }


WithdrawalReason = Literal["disputed_and_wrong", "rule_change"]


@dataclass(frozen=True)
class Withdrawal:
    """A finding taken back: a maintainer showed it wrong, or a rule fix showed it ours.

    A withheld finding withdrawn is never published. One already published stays
    visible, marked as our error.
    """

    server_id: str
    finding_id: str
    reason: WithdrawalReason
    at: datetime
    note: str

    def __post_init__(self) -> None:
        if self.reason not in get_args(WithdrawalReason):
            raise ValueError(f"reason must be one of {', '.join(get_args(WithdrawalReason))}")
        _aware(self.at, "at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "withdrawal",
            "server_id": self.server_id,
            "finding_id": self.finding_id,
            "reason": self.reason,
            "at": utc_stamp(self.at),
            "note": self.note,
        }


@dataclass(frozen=True)
class Extension:
    """More time agreed with a maintainer for one finding. It never shortens a window."""

    server_id: str
    finding_id: str
    until: datetime
    agreed_at: datetime
    note: str

    def __post_init__(self) -> None:
        _aware(self.until, "until")
        _aware(self.agreed_at, "agreed_at")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "extension",
            "server_id": self.server_id,
            "finding_id": self.finding_id,
            "until": utc_stamp(self.until),
            "agreed_at": utc_stamp(self.agreed_at),
            "note": self.note,
        }


Entry = Notice | OptOut | Withdrawal | Extension


def _when(record: Mapping[str, Any], name: str) -> datetime:
    moment = _parse(record[name])
    assert moment is not None
    return moment


def _from_dict(record: Mapping[str, Any]) -> Entry:
    if record["kind"] == "withdrawal":
        return Withdrawal(
            server_id=str(record["server_id"]),
            finding_id=str(record["finding_id"]),
            reason=record["reason"],
            at=_when(record, "at"),
            note=str(record.get("note", "")),
        )
    if record["kind"] == "extension":
        return Extension(
            server_id=str(record["server_id"]),
            finding_id=str(record["finding_id"]),
            until=_when(record, "until"),
            agreed_at=_when(record, "agreed_at"),
            note=str(record.get("note", "")),
        )
    if record["kind"] == "opt_out":
        requested = _parse(record["requested_at"])
        assert requested is not None
        return OptOut(server_id=str(record["server_id"]), requested_at=requested)
    if record["kind"] != "notice":
        raise ValueError(f"unknown ledger entry kind {record['kind']!r}")
    notified = _parse(record["notified_at"])
    assert notified is not None
    return Notice(
        server_id=str(record["server_id"]),
        finding_ids=tuple(str(i) for i in record["finding_ids"]),
        channel=record["channel"],
        notified_at=notified,
        reference=str(record["reference"]),
        verified_by=str(record["verified_by"]),
        acknowledged_at=_parse(record.get("acknowledged_at")),
        fixed_at=_parse(record.get("fixed_at")),
    )


def load_ledger(path: Path) -> list[Entry]:
    """Every entry, or none when there is no ledger: nobody has been notified."""
    if not path.exists():
        return []
    return [
        _from_dict(json.loads(line))
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_ledger(path: Path, entries: Iterable[Entry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(e.to_dict(), sort_keys=True) + "\n" for e in entries),
        encoding="utf-8",
    )


def check_notice(
    notice: Notice,
    *,
    history: Mapping[str, Mapping[str, Any]],
    verified: AbstractSet[str],
    now: datetime,
) -> None:
    """Refuse a notice the policy does not allow, before it can open any window."""
    if not notice.finding_ids:
        raise LedgerRefused("the notice names no finding; a window belongs to a named finding")
    if notice.notified_at > _aware(now, "now"):
        raise LedgerRefused("the notice is dated in the future")
    for finding_id in notice.finding_ids:
        record = history.get(finding_id)
        if record is None:
            raise LedgerRefused(f"{finding_id} is not in the history")
        if record["server_id"] != notice.server_id:
            raise LedgerRefused(f"{finding_id} belongs to {record['server_id']}, not {notice.server_id}")
        if finding_id not in verified:
            raise LedgerRefused(
                f"{finding_id} is not verified: no person has labelled it a true positive"
            )
        first_seen = _parse(str(record["first_seen"]))
        assert first_seen is not None
        if notice.notified_at < first_seen:
            raise LedgerRefused(
                f"the notice is dated before {finding_id} was first seen ({record['first_seen']})"
            )


def disclosure_records(entries: Sequence[Entry]) -> dict[str, DisclosureRecord]:
    """What the gate needs: notices, withdrawals, extensions and opt-outs, by server.

    The earliest window-opening notice names a finding's start, and the latest
    extension its end; a withdrawal holds for good.
    """
    notified: dict[str, dict[str, datetime]] = {}
    withdrawn: dict[str, set[str]] = {}
    extended: dict[str, dict[str, datetime]] = {}
    opted_out: set[str] = set()
    for entry in entries:
        if isinstance(entry, OptOut):
            opted_out.add(entry.server_id)
        elif isinstance(entry, Withdrawal):
            withdrawn.setdefault(entry.server_id, set()).add(entry.finding_id)
        elif isinstance(entry, Extension):
            ends = extended.setdefault(entry.server_id, {})
            ends[entry.finding_id] = max(entry.until, ends.get(entry.finding_id, entry.until))
        elif entry.channel in WINDOW_CHANNELS:
            dates = notified.setdefault(entry.server_id, {})
            for finding_id in entry.finding_ids:
                if finding_id not in dates or entry.notified_at < dates[finding_id]:
                    dates[finding_id] = entry.notified_at
    servers = notified.keys() | withdrawn.keys() | extended.keys() | opted_out
    return {
        server_id: DisclosureRecord(
            server_id=server_id,
            notified=notified.get(server_id, {}),
            opted_out=server_id in opted_out,
            withdrawn=frozenset(withdrawn.get(server_id, set())),
            extended=extended.get(server_id, {}),
        )
        for server_id in servers
    }


def _follow(
    by_id: Mapping[str, datetime],
    history: Sequence[Mapping[str, Any]],
    pick: Callable[[list[datetime]], datetime],
) -> dict[str, datetime]:
    """Carry dates keyed by finding id to each finding's current id, choosing with `pick`."""
    carried = dict(by_id)
    for finding in history:
        found = [carried[old] for old in finding.get("previous_ids", []) if old in carried]
        current = str(finding["finding_id"])
        if current in carried:
            found.append(carried[current])
        if found:
            carried[current] = pick(found)
    return carried


def follow_moves(
    records: Mapping[str, DisclosureRecord], history: Sequence[Mapping[str, Any]]
) -> dict[str, DisclosureRecord]:
    """Carry notices, withdrawals and extensions to the id each finding has now.

    A ledger entry names the id a finding had when it was written. If the
    maintainer then edits the file above it, the finding is re-keyed and the
    merge records the old id in `previous_ids`. Without this a notice would
    never complete, a withdrawal would stop protecting the finding, and an
    extension would be lost. The earliest notice and the latest extension win.
    """
    result: dict[str, DisclosureRecord] = {}
    for server, record in records.items():
        mine = [f for f in history if str(f["server_id"]) == server]
        withdrawn = set(record.withdrawn)
        for finding in mine:
            if withdrawn & set(finding.get("previous_ids", [])):
                withdrawn.add(str(finding["finding_id"]))
        result[server] = DisclosureRecord(
            server_id=server,
            notified=_follow(record.notified, mine, min),
            opted_out=record.opted_out,
            withdrawn=frozenset(withdrawn),
            extended=_follow(record.extended, mine, max),
        )
    return result
