import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from analyzer.models import Finding, Location
from analyzer.pipeline import FINDINGS_FILE, SARIF_FILE, SUMMARY_FILE, publish_from_history
from analyzer.report.gate import DisclosureRecord
from analyzer.report.merge import write_findings

NOW = datetime(2026, 9, 24, 12, 0, 0, tzinfo=UTC)


def _finding(n: int, severity: str = "medium") -> Finding:
    return Finding(
        server_id=f"owner/repo-{n}",
        commit_sha="a" * 40,
        rule_id="SCOPE-OVERBROAD",
        severity=severity,  # type: ignore[arg-type]
        confidence="low",
        location=Location(file="src/index.ts", line=n + 1),
        evidence=f"listens on 0.0.0.0 ({n})",
    )


def _prior_scan(data_dir: Path, scanned: int = 1642) -> None:
    """A previous scan's summary, which republication requires: coverage is
    measured by scanning and cannot be derived from the history."""
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / SUMMARY_FILE).write_text(
        json.dumps(
            {"generated_at": "2026-09-23T05:27:12Z", "scanned": scanned, "skipped": 358, "failed": 0}
        ),
        encoding="utf-8",
    )


def _history(path: Path, findings: list[Finding]) -> None:
    write_findings(
        path,
        [{**f.to_dict(), "first_seen": "2026-09-23T00:00:00Z", "last_seen": "2026-09-23T00:00:00Z"} for f in findings],
    )


def test_publishing_needs_no_scan(tmp_path: Path) -> None:
    """A thirteen-minute rescan to republish couples two unrelated things, and
    it means a disclosure window closing has no effect until a scan succeeds.
    """
    cache, data = tmp_path / "cache", tmp_path / "data"
    _prior_scan(data)
    _history(cache / "history.jsonl", [_finding(1), _finding(2)])

    result = publish_from_history(
        cache_dir=cache, data_dir=data, disclosure_records={}, now=NOW, tool_version="0.1.0"
    )

    assert result.published == 2
    assert (data / FINDINGS_FILE).exists()
    assert (data / SARIF_FILE).exists()


def test_the_gate_still_holds_when_publishing_without_a_scan(tmp_path: Path) -> None:
    """The point of separating them is convenience, not a second route past
    the gate. High and critical findings stay withheld here exactly as they do
    inside a scan run.
    """
    cache, data = tmp_path / "cache", tmp_path / "data"
    _prior_scan(data)
    _history(cache / "history.jsonl", [_finding(1, "critical"), _finding(2, "medium")])

    result = publish_from_history(
        cache_dir=cache, data_dir=data, disclosure_records={}, now=NOW, tool_version="0.1.0"
    )

    published = [json.loads(line) for line in (data / FINDINGS_FILE).read_text().splitlines()]
    assert result.published == 1
    assert result.withheld == 1
    assert [p["severity"] for p in published] == ["medium"]


def test_a_closed_window_publishes_without_waiting_for_a_scan(tmp_path: Path) -> None:
    """This is the case the coupling broke. A finding whose ninety days have
    elapsed should become publishable on its own, not on the next successful
    crawl of twenty-one thousand repositories.
    """
    cache, data = tmp_path / "cache", tmp_path / "data"
    _prior_scan(data)
    _history(cache / "history.jsonl", [_finding(1, "critical")])
    records = {
        "owner/repo-1": DisclosureRecord(
            server_id="owner/repo-1", notified_at=NOW - timedelta(days=120)
        )
    }

    result = publish_from_history(
        cache_dir=cache, data_dir=data, disclosure_records=records, now=NOW, tool_version="0.1.0"
    )

    assert result.published == 1


def test_a_missing_history_is_refused_rather_than_publishing_nothing(tmp_path: Path) -> None:
    """Writing an empty data/ would replace a good publication with nothing
    and look exactly like an ecosystem that fixed itself."""
    with pytest.raises(FileNotFoundError):
        publish_from_history(
            cache_dir=tmp_path / "cache",
            data_dir=tmp_path / "data",
            disclosure_records={},
            now=NOW,
            tool_version="0.1.0",
        )


def test_the_summary_keeps_the_scan_it_describes_and_dates_the_publication(
    tmp_path: Path,
) -> None:
    """Republishing does not rescan, so the coverage figures still belong to
    the scan that produced them. Overwriting generated_at would date a
    1,642-server scan to a day nothing was scanned, and a reader comparing the
    two would be misled about when the corpus was examined.
    """
    cache, data = tmp_path / "cache", tmp_path / "data"
    data.mkdir(parents=True)
    (data / SUMMARY_FILE).write_text(
        json.dumps({"generated_at": "2026-09-23T05:27:12Z", "scanned": 1642, "skipped": 358, "failed": 0}),
        encoding="utf-8",
    )
    _history(cache / "history.jsonl", [_finding(1)])

    publish_from_history(
        cache_dir=cache, data_dir=data, disclosure_records={}, now=NOW, tool_version="0.1.0"
    )

    summary = json.loads((data / SUMMARY_FILE).read_text())
    assert summary["scanned"] == 1642
    assert summary["generated_at"] == "2026-09-23T05:27:12Z"
    assert summary["published_at"] == "2026-09-24T12:00:00Z"


def test_publishing_without_a_prior_scan_summary_is_refused(tmp_path: Path) -> None:
    """Coverage cannot be republished, because it was never measured here.

    The history records findings, not how many servers were scanned - 306 of
    1,642 produced anything. So a republication has no way to know the
    denominator, and writing a summary without it publishes findings with no
    coverage figure at all. Success criterion 1 is about coverage, so that
    summary would fail the criterion while looking complete.
    """
    cache = tmp_path / "cache"
    _history(cache / "history.jsonl", [_finding(1)])

    with pytest.raises(ValueError, match="scanned"):
        publish_from_history(
            cache_dir=cache,
            data_dir=tmp_path / "data",
            disclosure_records={},
            now=NOW,
            tool_version="0.1.0",
        )


def test_the_scan_date_is_never_moved_to_the_publication_date(tmp_path: Path) -> None:
    """Dating a scan to a day nothing was scanned misstates when the corpus was
    examined, which is the one figure a reader uses to judge how current the
    results are."""
    cache, data = tmp_path / "cache", tmp_path / "data"
    data.mkdir(parents=True)
    (data / SUMMARY_FILE).write_text(
        json.dumps({"generated_at": "2026-09-23T05:27:12Z", "scanned": 1642, "skipped": 358, "failed": 0}),
        encoding="utf-8",
    )
    _history(cache / "history.jsonl", [_finding(1)])

    publish_from_history(
        cache_dir=cache, data_dir=data, disclosure_records={}, now=NOW, tool_version="0.1.0"
    )

    summary = json.loads((data / SUMMARY_FILE).read_text())
    assert summary["generated_at"] == "2026-09-23T05:27:12Z"
    assert summary["scanned"] == 1642
