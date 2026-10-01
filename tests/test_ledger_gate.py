import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from analyzer.cli import _build_parser, disclosure_from_ledger, main, run_index_scan
from analyzer.crawler.index import write_server_index
from analyzer.crawler.registry import ServerRecord
from analyzer.fetcher.clone import CloneResult
from analyzer.models import Finding, Location
from analyzer.report.gate import DISCLOSURE_WINDOW
from analyzer.report.ledger import Notice, load_ledger, write_ledger
from analyzer.report.vault import seal
from analyzer.scanner import ScanReport

NOW = datetime(2027, 3, 1, 3, 10, tzinfo=UTC)
KEY = "f" * 64
SERVER = "owner/repo"


def _finding() -> Finding:
    return Finding(
        server_id=SERVER,
        commit_sha="a" * 40,
        rule_id="PATH-TRAVERSAL",
        severity="critical",
        confidence="high",
        location=Location(file="src/files.ts", line=3),
        evidence="fs.readFile(args.path)",
    )


def _clone(repo_url: str, destination: Path) -> CloneResult:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "package.json").write_text(
        '{"dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}', encoding="utf-8"
    )
    (destination / "index.ts").write_text(
        'import { Server } from "@modelcontextprotocol/sdk/server/index.js";', encoding="utf-8"
    )
    return CloneResult(path=destination, commit_sha="a" * 40)


def _scan(directory: Path, server_id: str, commit_sha: str) -> ScanReport:
    return ScanReport(findings=(_finding(),), skipped=())


def _published(tmp_path: Path, ledger: Path) -> int:
    index = tmp_path / "index.jsonl"
    write_server_index(
        index,
        [ServerRecord(server_id=SERVER, repo_url=f"https://github.com/{SERVER}", discovered_via="registry")],
    )
    return run_index_scan(
        index_path=index,
        data_dir=tmp_path / "data",
        cache_dir=tmp_path / "cache",
        clone=_clone,
        scan=_scan,
        now=lambda: NOW,
        disclosure_records=disclosure_from_ledger(ledger),
    ).published


def test_a_closed_window_on_the_ledger_publishes_the_finding_it_named(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger.jsonl"
    write_ledger(
        ledger,
        [
            Notice(
                server_id=SERVER,
                finding_ids=(_finding().finding_id,),
                channel="private_advisory",
                notified_at=NOW - DISCLOSURE_WINDOW - timedelta(days=1),
                reference="email",
                verified_by="manan",
            )
        ],
    )
    assert _published(tmp_path, ledger) == 1


def test_no_ledger_means_nobody_was_notified_and_nothing_serious_publishes(tmp_path: Path) -> None:
    assert _published(tmp_path, tmp_path / "absent.jsonl") == 0


def test_the_scan_reads_the_opened_ledger_by_default() -> None:
    args = _build_parser().parse_args(["scan", "--index", "x.jsonl"])
    assert args.ledger == ".cache/ledger.jsonl"


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is not installed")
def test_opening_a_sealed_ledger_and_a_missing_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HISTORY_KEY", KEY)
    plain, sealed, opened = tmp_path / "l.jsonl", tmp_path / "l.jsonl.gpg", tmp_path / "out.jsonl"
    write_ledger(plain, [])
    plain.write_text('{"kind": "opt_out", "server_id": "a/b", "requested_at": "2026-11-01T00:00:00Z"}\n')
    seal(plain, sealed, KEY)

    assert main(["ledger", "open", "--sealed", str(sealed), "--out", str(opened)]) == 0
    assert [e.server_id for e in load_ledger(opened)] == ["a/b"]

    assert main(["ledger", "open", "--sealed", str(tmp_path / "none.gpg"), "--out", str(opened)]) == 0
    assert load_ledger(opened) == [], "no ledger yet must read as nobody notified"


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is not installed")
def test_a_tampered_ledger_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A planted ledger with old dates would publish withheld findings early,
    # the one direction the gate must never err in.
    monkeypatch.setenv("HISTORY_KEY", KEY)
    plain, sealed = tmp_path / "l.jsonl", tmp_path / "l.jsonl.gpg"
    plain.write_text('{"kind": "opt_out", "server_id": "a/b", "requested_at": "2026-11-01T00:00:00Z"}\n')
    seal(plain, sealed, KEY)
    data = bytearray(sealed.read_bytes())
    data[len(data) // 2] ^= 1
    sealed.write_bytes(bytes(data))
    assert main(["ledger", "open", "--sealed", str(sealed), "--out", str(tmp_path / "o.jsonl")]) != 0
    assert not (tmp_path / "o.jsonl").exists()


def test_the_scan_command_hands_the_ledger_to_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without this, the command could keep passing no notices while every
    # function beneath it was tested, which is how the gate went unfed before.
    from analyzer import cli
    from analyzer.pipeline import PipelineResult

    ledger = tmp_path / "ledger.jsonl"
    write_ledger(
        ledger,
        [
            Notice(
                server_id=SERVER,
                finding_ids=("f-1",),
                channel="private_advisory",
                notified_at=NOW,
                reference="email",
                verified_by="manan",
            )
        ],
    )
    seen: dict[str, object] = {}

    def capture(**kwargs: object) -> PipelineResult:
        seen.update(kwargs)
        return PipelineResult(scanned=0, skipped=0, failed=0, published=0, withheld=0)

    monkeypatch.setattr(cli, "run_index_scan", capture)
    main(["scan", "--index", str(tmp_path / "i.jsonl"), "--ledger", str(ledger)])
    assert seen["disclosure_records"] == disclosure_from_ledger(ledger)
