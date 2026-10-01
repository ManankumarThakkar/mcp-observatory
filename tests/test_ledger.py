from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from analyzer.models import Finding, Location
from analyzer.report.gate import DISCLOSURE_WINDOW, disclosure_state
from analyzer.report.ledger import (
    LedgerRefused,
    Notice,
    OptOut,
    check_notice,
    disclosure_records,
    load_ledger,
    write_ledger,
)

NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
FIRST_SEEN = "2026-10-02T03:20:00Z"


def _finding(n: int = 1, server_id: str = "acme/notes") -> Finding:
    return Finding(
        server_id=server_id,
        commit_sha="a" * 40,
        rule_id="PATH-TRAVERSAL",
        severity="critical",
        confidence="high",
        location=Location(file="src/files.ts", line=n),
        evidence=f"fs.readFile(args.path) {n}",
    )


def _history(*findings: Finding) -> dict[str, dict[str, Any]]:
    return {
        f.finding_id: {**f.to_dict(), "first_seen": FIRST_SEEN, "last_seen": FIRST_SEEN}
        for f in findings
    }


def _notice(*findings: Finding, **overrides: Any) -> Notice:
    fields: dict[str, Any] = {
        "server_id": "acme/notes",
        "finding_ids": tuple(f.finding_id for f in findings),
        "channel": "private_advisory",
        "notified_at": NOW - timedelta(days=1),
        "reference": "https://github.com/acme/notes/security/advisories/GHSA-xxxx",
        "verified_by": "manan",
    }
    return Notice(**{**fields, **overrides})


# --- what a notice may record --------------------------------------------------


def test_a_verified_finding_on_its_own_server_can_be_recorded() -> None:
    f = _finding()
    check_notice(_notice(f), history=_history(f), verified={f.finding_id}, now=NOW)


def test_a_finding_no_person_verified_is_refused() -> None:
    # The approved policy: notify only what a person verified. Enforced here
    # so a rushed batch or a typo cannot report an unverified alert.
    f = _finding()
    with pytest.raises(LedgerRefused, match="not verified"):
        check_notice(_notice(f), history=_history(f), verified=set(), now=NOW)


def test_a_finding_not_in_the_history_is_refused() -> None:
    f = _finding()
    with pytest.raises(LedgerRefused, match="not in the history"):
        check_notice(_notice(f), history={}, verified={f.finding_id}, now=NOW)


def test_a_finding_from_another_server_is_refused() -> None:
    other = _finding(server_id="someone/else")
    with pytest.raises(LedgerRefused, match="belongs to someone/else"):
        check_notice(_notice(other), history=_history(other), verified={other.finding_id}, now=NOW)


def test_a_notice_naming_nothing_is_refused() -> None:
    with pytest.raises(LedgerRefused, match="names no finding"):
        check_notice(_notice(), history={}, verified=set(), now=NOW)


def test_a_notice_dated_in_the_future_is_refused() -> None:
    f = _finding()
    with pytest.raises(LedgerRefused, match="future"):
        check_notice(
            _notice(f, notified_at=NOW + timedelta(hours=1)),
            history=_history(f),
            verified={f.finding_id},
            now=NOW,
        )


def test_a_notice_before_the_finding_existed_is_refused() -> None:
    # It cannot have described a finding the scanner had not yet produced, and
    # an early date would close the window early.
    f = _finding()
    with pytest.raises(LedgerRefused, match="before"):
        check_notice(
            _notice(f, notified_at=datetime(2026, 9, 1, tzinfo=UTC)),
            history=_history(f),
            verified={f.finding_id},
            now=NOW,
        )


def test_an_unknown_channel_is_refused() -> None:
    with pytest.raises(ValueError, match="channel"):
        _notice(_finding(), channel="tweet")


def test_a_naive_date_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone"):
        _notice(_finding(), notified_at=datetime(2026, 11, 1))  # noqa: DTZ001


# --- what the gate receives ----------------------------------------------------


def test_a_private_notice_opens_the_window_for_the_findings_it_names() -> None:
    named, unnamed = _finding(1), _finding(2)
    sent = NOW - DISCLOSURE_WINDOW - timedelta(days=1)
    records = disclosure_records([_notice(named, notified_at=sent)])
    record = records["acme/notes"]
    assert disclosure_state(named, record, now=NOW) == "disclosed"
    assert disclosure_state(unnamed, record, now=NOW) == "withheld"


def test_a_request_for_a_contact_opens_no_window() -> None:
    # The public issue asks only for a contact and describes nothing, so no
    # maintainer has been told about any finding yet.
    f = _finding()
    sent = NOW - DISCLOSURE_WINDOW - timedelta(days=1)
    records = disclosure_records([_notice(f, channel="contact_request", notified_at=sent)])
    assert disclosure_state(f, records.get("acme/notes"), now=NOW) == "withheld"


def test_the_earliest_notice_naming_a_finding_starts_its_window() -> None:
    f = _finding()
    early, late = NOW - timedelta(days=100), NOW - timedelta(days=10)
    records = disclosure_records([_notice(f, notified_at=late), _notice(f, notified_at=early)])
    assert records["acme/notes"].notified[f.finding_id] == early


def test_an_opt_out_reaches_the_gate() -> None:
    f = _finding()
    records = disclosure_records([OptOut(server_id="acme/notes", requested_at=NOW)])
    assert disclosure_state(f, records["acme/notes"], now=NOW) == "opted_out"


# --- the file ------------------------------------------------------------------


def test_the_ledger_round_trips_through_its_file(tmp_path: Path) -> None:
    f = _finding()
    entries: list[Notice | OptOut] = [
        _notice(f, acknowledged_at=NOW),
        OptOut(server_id="other/server", requested_at=NOW),
    ]
    write_ledger(tmp_path / "ledger.jsonl", entries)
    assert load_ledger(tmp_path / "ledger.jsonl") == entries


def test_a_missing_ledger_means_nobody_has_been_notified(tmp_path: Path) -> None:
    # The safe direction: no notices, so every serious finding stays withheld.
    assert load_ledger(tmp_path / "absent.jsonl") == []
