import json
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from analyzer.cli import main
from analyzer.models import Finding, Location
from analyzer.report.gate import DISCLOSURE_WINDOW
from analyzer.report.ledger_store import fetch_ledger
from analyzer.report.merge import utc_stamp
from analyzer.report.vault import seal

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is not installed")

KEY = "e" * 64
# Relative to the real clock, because the ledger refuses a notice dated in the
# future; fixed dates would make these tests fail once the calendar passed them.
SENT = datetime.now(UTC).replace(microsecond=0) - timedelta(days=1)
FIRST_SEEN = utc_stamp(SENT - timedelta(days=9))
FINDING = Finding(
    server_id="acme/notes",
    commit_sha="a" * 40,
    rule_id="PATH-TRAVERSAL",
    severity="critical",
    confidence="high",
    location=Location(file="src/files.ts", line=3),
    evidence="fs.readFile(args.path)",
)


def _git(repo: Path, *args: str, stdin: str | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], input=stdin, check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A clone whose origin has a sealed history on nightly-data, and one label."""
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True, capture_output=True)
    _git(clone, "config", "user.email", "test@example.com")
    _git(clone, "config", "user.name", "Test")

    plain, sealed = tmp_path / "history.jsonl", tmp_path / "history.jsonl.gpg"
    plain.write_text(
        json.dumps({**FINDING.to_dict(), "first_seen": FIRST_SEEN, "last_seen": FIRST_SEEN}) + "\n"
    )
    seal(plain, sealed, KEY)
    blob = _git(clone, "hash-object", "-w", str(sealed)).strip()
    tree = _git(clone, "mktree", stdin=f"100644 blob {blob}\thistory.jsonl.gpg\n").strip()
    commit = _git(clone, "commit-tree", tree, "-m", "trend").strip()
    _git(clone, "push", "-q", "origin", f"{commit}:refs/heads/nightly-data")

    (clone / ".cache" / "annotations").mkdir(parents=True)
    (clone / ".cache" / "golden-entries.jsonl").write_text(
        json.dumps({"entry_id": "g-1", "finding_id": FINDING.finding_id}) + "\n"
    )
    monkeypatch.chdir(clone)
    monkeypatch.setenv("HISTORY_KEY", KEY)
    return clone


def _label(repo: Path, label: str) -> None:
    (repo / ".cache" / "annotations" / "manan.jsonl").write_text(
        json.dumps({"entry_id": "g-1", "label": label, "reason": "", "annotator": "manan"}) + "\n"
    )


ADD = [
    "ledger", "add", "--server", "acme/notes", "--finding", FINDING.finding_id,
    "--channel", "private_advisory", "--notified-at", utc_stamp(SENT),
    "--reference", "email", "--annotator", "manan",
]


def test_a_verified_finding_is_recorded_on_the_ledger_branch(repo: Path) -> None:
    _label(repo, "true_positive")
    assert main(ADD) == 0
    entries, _ = fetch_ledger(repo, key=KEY)
    assert [e.server_id for e in entries] == ["acme/notes"]


def test_an_unverified_finding_is_refused_in_a_sentence(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _label(repo, "false_positive")
    assert main(ADD) != 0
    assert "not verified" in capsys.readouterr().err
    assert fetch_ledger(repo, key=KEY) == ([], None)


def test_acknowledgement_and_opt_out_are_recorded(repo: Path) -> None:
    _label(repo, "true_positive")
    main(ADD)
    entries, _ = fetch_ledger(repo, key=KEY)
    notice_id = entries[0].notice_id  # type: ignore[union-attr]
    later = utc_stamp(SENT + timedelta(hours=1))
    assert main(["ledger", "mark", "--notice", notice_id, "--acknowledged-at", later]) == 0
    assert main(["ledger", "opt-out", "--server", "other/server", "--requested-at", later]) == 0
    entries, _ = fetch_ledger(repo, key=KEY)
    assert entries[0].acknowledged_at is not None  # type: ignore[union-attr]
    assert entries[1].server_id == "other/server"


def test_show_prints_counts_and_dates_but_no_server(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _label(repo, "true_positive")
    main(ADD)
    capsys.readouterr()
    assert main(["ledger", "show"]) == 0
    out = capsys.readouterr().out
    assert "1 notice" in out
    closes = (SENT + DISCLOSURE_WINDOW).date().isoformat()
    assert closes in out, "the window closing date is what show is for"
    assert "acme/notes" not in out


def test_a_withdrawal_and_an_extension_are_recorded_against_a_known_finding(repo: Path) -> None:
    from analyzer.report.ledger import Extension, Withdrawal

    when = utc_stamp(SENT)
    later = utc_stamp(SENT + DISCLOSURE_WINDOW + timedelta(days=30))
    assert main(["ledger", "withdraw", "--finding", FINDING.finding_id, "--reason", "disputed_and_wrong", "--at", when, "--note", "guarded upstream"]) == 0
    assert main(["ledger", "extend", "--finding", FINDING.finding_id, "--until", later, "--agreed-at", when]) == 0
    entries, _ = fetch_ledger(repo, key=KEY)
    assert isinstance(entries[0], Withdrawal) and entries[0].server_id == "acme/notes"
    assert isinstance(entries[1], Extension) and entries[1].finding_id == FINDING.finding_id


def test_withdrawing_a_finding_not_in_the_history_is_refused(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["ledger", "withdraw", "--finding", "no-such-finding", "--reason", "rule_change", "--at", utc_stamp(SENT)]) != 0
    assert "not in the history" in capsys.readouterr().err
    assert fetch_ledger(repo, key=KEY) == ([], None)
