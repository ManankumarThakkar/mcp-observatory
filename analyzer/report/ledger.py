"""The disclosure ledger: which findings were reported to which maintainer, and when.

It is the only source of the dates the gate opens windows from, so every rule
about what a notice may record lives here, next to the record itself.
"""

import json
from collections.abc import Iterable, Mapping, Sequence
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


Entry = Notice | OptOut


def _from_dict(record: Mapping[str, Any]) -> Entry:
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
    """What the gate needs: each finding's earliest window-opening notice, and opt-outs."""
    notified: dict[str, dict[str, datetime]] = {}
    opted_out: set[str] = set()
    for entry in entries:
        if isinstance(entry, OptOut):
            opted_out.add(entry.server_id)
            continue
        if entry.channel not in WINDOW_CHANNELS:
            continue
        dates = notified.setdefault(entry.server_id, {})
        for finding_id in entry.finding_ids:
            if finding_id not in dates or entry.notified_at < dates[finding_id]:
                dates[finding_id] = entry.notified_at
    return {
        server_id: DisclosureRecord(
            server_id=server_id,
            notified=notified.get(server_id, {}),
            opted_out=server_id in opted_out,
        )
        for server_id in notified.keys() | opted_out
    }
