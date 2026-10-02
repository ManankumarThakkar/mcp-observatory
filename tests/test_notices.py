from datetime import UTC, datetime, timedelta
from typing import Any

from analyzer.report.channels import ChannelSuggestion
from analyzer.report.gate import DISCLOSURE_WINDOW
from analyzer.report.ledger import Notice, OptOut
from analyzer.report.notices import (
    NOTICE_TEXT,
    REWORK_MARK,
    render_contact_request,
    render_notice,
    select_findings,
)
from analyzer.rules import ALL_RULES

NOW = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)
COMMIT = "b" * 40


def _record(n: int, server: str = "acme/notes", rule: str = "PATH-TRAVERSAL") -> dict[str, Any]:
    return {
        "finding_id": f"f-{server}-{n}",
        "server_id": server,
        "rule_id": rule,
        "severity": "critical",
        "commit_sha": COMMIT,
        "location": {"file": "src/files.ts", "line": 10 + n},
        "evidence": f"fs.readFile(args.path) {n}",
        "first_seen": "2026-10-02T03:20:00Z",
        "last_seen": "2026-11-01T03:20:00Z",
    }


def _history(*records: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["finding_id"]: r for r in records}


def _sent(*finding_ids: str, channel: str = "private_advisory") -> Notice:
    return Notice(
        server_id="acme/notes",
        finding_ids=finding_ids,
        channel=channel,  # type: ignore[arg-type]
        notified_at=NOW - timedelta(days=3),
        reference="email",
        verified_by="manan",
    )


# --- which findings get a draft --------------------------------------------------


def test_only_verified_findings_are_drafted_grouped_by_server() -> None:
    a, b, c = _record(1), _record(2), _record(1, server="other/server")
    selection = select_findings(
        _history(a, b, c), verified={a["finding_id"]: "why a", c["finding_id"]: "why c"}, ledger=[]
    )
    assert {s: [f.record["finding_id"] for f in fs] for s, fs in selection.drafts.items()} == {
        "acme/notes": [a["finding_id"]],
        "other/server": [c["finding_id"]],
    }


def test_a_finding_already_named_in_a_private_notice_is_not_drafted_again() -> None:
    a, b = _record(1), _record(2)
    selection = select_findings(
        _history(a, b),
        verified={a["finding_id"]: "", b["finding_id"]: ""},
        ledger=[_sent(a["finding_id"])],
    )
    assert [f.record["finding_id"] for f in selection.drafts["acme/notes"]] == [b["finding_id"]]
    assert selection.already_notified == 1


def test_a_contact_request_does_not_count_as_notified() -> None:
    # It described nothing, so the private notice still has to be sent.
    a = _record(1)
    selection = select_findings(
        _history(a), verified={a["finding_id"]: ""}, ledger=[_sent(a["finding_id"], channel="contact_request")]
    )
    assert "acme/notes" in selection.drafts


def test_an_opted_out_server_gets_no_draft() -> None:
    a = _record(1)
    selection = select_findings(
        _history(a),
        verified={a["finding_id"]: ""},
        ledger=[OptOut(server_id="acme/notes", requested_at=NOW)],
    )
    assert selection.drafts == {}
    assert selection.opted_out == 1


def test_a_verified_finding_the_scanner_no_longer_produces_is_skipped_and_counted() -> None:
    # Telling a maintainer about code that has already changed wastes their time.
    selection = select_findings({}, verified={"f-gone": "real"}, ledger=[])
    assert selection.drafts == {}
    assert selection.no_longer_produced == 1


# --- what a draft says -------------------------------------------------------------


def _draft(channel: ChannelSuggestion | None = None) -> str:
    a = _record(1)
    selection = select_findings(_history(a), verified={a["finding_id"]: "args.path is joined unchecked"}, ledger=[])
    return render_notice(
        "acme/notes", "https://github.com/acme/notes", selection.drafts["acme/notes"], channel, now=NOW
    )


def test_the_draft_links_the_exact_line_at_the_commit_scanned() -> None:
    assert f"https://github.com/acme/notes/blob/{COMMIT}/src/files.ts#L11" in _draft()


def test_the_draft_quotes_the_labelling_reason_marked_for_rework() -> None:
    draft = _draft()
    assert "args.path is joined unchecked" in draft
    assert REWORK_MARK in draft


def test_the_draft_states_when_the_window_would_close_if_sent_today() -> None:
    assert (NOW + DISCLOSURE_WINDOW).date().isoformat() in _draft()


def test_the_draft_says_how_to_dispute_ask_for_time_or_opt_out() -> None:
    draft = _draft().lower()
    assert "dispute" in draft
    assert "more time" in draft
    assert "opt out" in draft
    assert "verified by one person" in draft


def test_the_draft_names_the_suggested_channel() -> None:
    channel = ChannelSuggestion(
        channel="private_advisory", url="https://github.com/acme/notes/security/advisories/new"
    )
    assert "https://github.com/acme/notes/security/advisories/new" in _draft(channel)


def test_the_draft_ends_with_the_ledger_command_to_run_after_sending() -> None:
    assert "mcp-observatory ledger add --server acme/notes --finding f-acme/notes-1" in _draft()


def test_every_rule_has_notice_text() -> None:
    # Derived from the rules themselves, so a new rule without notice text fails.
    assert set(NOTICE_TEXT) == {rule.rule_id for rule in ALL_RULES}


def test_the_contact_request_describes_no_finding() -> None:
    # It is public. Nothing in it may say what was found or where.
    text = render_contact_request("acme/notes")
    for detail in ("src/files.ts", "PATH-TRAVERSAL", "fs.readFile", COMMIT, "#L"):
        assert detail not in text
    assert "security contact" in text.lower()
