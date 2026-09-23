import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from analyzer.crawler.registry import ServerRecord
from analyzer.fetcher.clone import CloneResult
from analyzer.models import Finding, Location
from analyzer.orchestrator import ScanFn
from analyzer.pipeline import CollapsedRun, PipelineResult, run_pipeline
from analyzer.report.gate import DISCLOSURE_WINDOW, DisclosureRecord
from analyzer.report.merge import load_previous
from analyzer.scanner import ScanReport
from analyzer.validation import ServerEvidence

NOW = datetime(2026, 9, 20, tzinfo=UTC)
SHA = "a" * 40


def _record(server_id: str = "acme/thing", via: str = "registry") -> ServerRecord:
    return ServerRecord(
        server_id=server_id,
        repo_url=f"https://github.com/{server_id}",
        discovered_via=via,
    )


def _clone_ok(url: str, dest: Path) -> CloneResult:
    dest.mkdir(parents=True, exist_ok=True)
    return CloneResult(path=dest, commit_sha=SHA)


def _finding(server_id: str, severity: str = "critical", line: int = 1) -> Finding:
    return Finding(
        server_id=server_id,
        commit_sha=SHA,
        rule_id="UNICODE-CONCEAL",
        severity=severity,  # type: ignore[arg-type]
        confidence="high",
        location=Location(file="src/index.ts", line=line),
        evidence=f"unicode-tag-block at line {line}",
    )


def _scanner(severity: str = "critical") -> ScanFn:
    def scan(root: Path, server_id: str, commit_sha: str) -> ScanReport:
        return ScanReport(findings=(_finding(server_id, severity),), skipped=())

    return scan


def _run(
    tmp_path: Path,
    records: list[ServerRecord],
    *,
    scan: ScanFn | None = None,
    disclosure: dict[str, DisclosureRecord] | None = None,
    now: datetime = NOW,
) -> PipelineResult:
    return run_pipeline(
        records,
        clone=_clone_ok,
        scan=scan or _scanner(),
        workdir=tmp_path / "work",
        data_dir=tmp_path / "data",
        cache_dir=tmp_path / "cache",
        disclosure_records=disclosure or {},
        now=now,
        tool_version="0.1.0",
        validate=lambda root: ServerEvidence(is_server=True, marker="x", path="y"),
    )


# --- it actually runs end to end ---------------------------------------------

def test_a_run_walks_scan_merge_gate_and_emit(tmp_path: Path) -> None:
    """Tasks 1 to 11 build eleven components and connect none of them.

    Without this there is a green suite and no way to produce a nightly run.
    """
    result = _run(tmp_path, [_record("a/one"), _record("b/two")], scan=_scanner("medium"))

    assert isinstance(result, PipelineResult)
    assert result.scanned == 2
    assert result.published == 2
    assert (tmp_path / "data" / "findings.jsonl").exists()
    assert (tmp_path / "data" / "findings.sarif").exists()
    assert (tmp_path / "data" / "summary.json").exists()


def test_the_full_history_stays_out_of_the_published_directory(tmp_path: Path) -> None:
    """A withheld finding must not reach a public file, but must stay in history.

    The window is 90 days. If the record vanished from history while withheld
    and returned on disclosure, first_seen would reset and the trend would
    show a gap that never happened.
    """
    _run(tmp_path, [_record("a/one")])  # critical, nobody notified -> withheld

    published = load_previous(tmp_path / "data" / "findings.jsonl")
    history = load_previous(tmp_path / "cache" / "history.jsonl")

    assert published == []
    assert len(history) == 1


def test_a_disclosed_finding_keeps_the_date_it_was_first_seen(tmp_path: Path) -> None:
    """The point of keeping history locally through the window.

    A finding published after 90 days is not new, and saying it is would
    understate how long the ecosystem carried it.
    """
    _run(tmp_path, [_record("a/one")], now=NOW)

    later = NOW + DISCLOSURE_WINDOW + timedelta(days=2)
    disclosure = {"a/one": DisclosureRecord("a/one", notified_at=NOW, opted_out=False)}
    _run(tmp_path, [_record("a/one")], disclosure=disclosure, now=later)

    published = load_previous(tmp_path / "data" / "findings.jsonl")
    assert len(published) == 1
    assert published[0]["first_seen"] == "2026-09-20T00:00:00Z"
    assert published[0]["disclosure_state"] == "disclosed"


def test_aggregate_counts_publish_even_when_findings_do_not(tmp_path: Path) -> None:
    """Spec section 11: aggregate statistics publish immediately."""
    _run(tmp_path, [_record("a/one"), _record("b/two")])

    summary = json.loads((tmp_path / "data" / "summary.json").read_text(encoding="utf-8"))
    assert summary["disclosure"]["withheld"] == 2
    assert summary["scanned"] == 2


def test_a_candidate_that_cannot_prove_itself_contributes_nothing(tmp_path: Path) -> None:
    """The validation gate from Task 3 has to hold all the way to publication."""
    result = run_pipeline(
        [_record("a/one", via="code-search")],
        clone=_clone_ok,
        scan=_scanner("medium"),
        workdir=tmp_path / "work",
        data_dir=tmp_path / "data",
        cache_dir=tmp_path / "cache",
        disclosure_records={},
        now=NOW,
        tool_version="0.1.0",
        validate=lambda root: ServerEvidence(is_server=False),
    )

    assert result.published == 0
    assert load_previous(tmp_path / "data" / "findings.jsonl") == []


# --- refusing to publish a broken run ----------------------------------------

def test_a_collapsed_run_refuses_to_publish(tmp_path: Path) -> None:
    """A crawl returning almost nothing is a broken upstream, not a clean ecosystem.

    A parser cannot tell one odd record from a systemic break. The pipeline
    can: it has last night's number to compare against.
    """
    _run(tmp_path, [_record(f"s/{n}") for n in range(20)], scan=_scanner("medium"))

    with pytest.raises(CollapsedRun, match="20"):
        _run(tmp_path, [_record("s/0")], scan=_scanner("medium"))


def test_a_collapsed_run_leaves_the_previous_publication_intact(tmp_path: Path) -> None:
    """Refusing must not damage what was already published."""
    _run(tmp_path, [_record(f"s/{n}") for n in range(20)], scan=_scanner("medium"))
    before = (tmp_path / "data" / "findings.jsonl").read_text(encoding="utf-8")

    with pytest.raises(CollapsedRun):
        _run(tmp_path, [_record("s/0")], scan=_scanner("medium"))

    assert (tmp_path / "data" / "findings.jsonl").read_text(encoding="utf-8") == before


def test_a_smaller_but_plausible_run_still_publishes(tmp_path: Path) -> None:
    """Servers disappear. The guard is for collapse, not for ordinary drift."""
    _run(tmp_path, [_record(f"s/{n}") for n in range(20)], scan=_scanner("medium"))

    result = _run(tmp_path, [_record(f"s/{n}") for n in range(18)], scan=_scanner("medium"))

    assert result.scanned == 18


def test_the_first_run_has_nothing_to_collapse_from(tmp_path: Path) -> None:
    result = _run(tmp_path, [_record("a/one")], scan=_scanner("medium"))

    assert result.scanned == 1


# --- partial runs -------------------------------------------------------------

def test_a_server_that_failed_tonight_keeps_its_earlier_findings(tmp_path: Path) -> None:
    """Spec section 9's partial-run tolerance, carried through the pipeline."""
    _run(tmp_path, [_record("a/one"), _record("b/two")], scan=_scanner("medium"))

    def explode(url: str, dest: Path) -> CloneResult:
        if "b/two" in url:
            raise RuntimeError("git exploded")
        return _clone_ok(url, dest)

    result = run_pipeline(
        [_record("a/one"), _record("b/two")],
        clone=explode,
        scan=_scanner("medium"),
        workdir=tmp_path / "work",
        data_dir=tmp_path / "data",
        cache_dir=tmp_path / "cache",
        disclosure_records={},
        now=NOW + timedelta(days=1),
        tool_version="0.1.0",
        validate=lambda root: ServerEvidence(is_server=True, marker="x", path="y"),
    )

    assert result.failed == 1
    published = {r["server_id"] for r in load_previous(tmp_path / "data" / "findings.jsonl")}
    assert published == {"a/one", "b/two"}, "a failed scan is not a fixed server"


def test_the_sarif_document_carries_only_published_findings(tmp_path: Path) -> None:
    _run(tmp_path, [_record("a/one"), _record("b/two")], scan=_scanner("critical"))

    document = json.loads((tmp_path / "data" / "findings.sarif").read_text(encoding="utf-8"))
    assert document["runs"][0]["results"] == []
