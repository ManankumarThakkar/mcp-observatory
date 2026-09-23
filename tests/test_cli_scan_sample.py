from datetime import UTC, datetime
from pathlib import Path

import pytest

from analyzer.cli import (
    DEFAULT_SAMPLE_SEED,
    EXIT_SCAN_FAILED,
    main,
    run_index_scan,
)
from analyzer.crawler.index import write_server_index
from analyzer.crawler.registry import ServerRecord
from analyzer.fetcher.clone import CloneResult
from analyzer.orchestrator import CloneFn
from analyzer.pipeline import PipelineResult
from analyzer.scanner import ScanReport

FIXED_NOW = datetime(2026, 9, 23, 6, 0, 0, tzinfo=UTC)


def _index(path: Path, count: int) -> Path:
    write_server_index(
        path,
        [
            ServerRecord(
                server_id=f"owner/repo-{n:04d}",
                repo_url=f"https://github.com/owner/repo-{n:04d}",
                discovered_via="registry",
            )
            for n in range(count)
        ],
    )
    return path


def _recording_clone(seen: list[str]) -> CloneFn:
    def clone(repo_url: str, destination: Path) -> CloneResult:
        seen.append(repo_url)
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "package.json").write_text(
            '{"dependencies": {"@modelcontextprotocol/sdk": "1.0.0"}}', encoding="utf-8"
        )
        (destination / "index.ts").write_text(
            'import { Server } from "@modelcontextprotocol/sdk/server/index.js";',
            encoding="utf-8",
        )
        return CloneResult(path=destination, commit_sha="a" * 40)

    return clone


def _no_findings(directory: Path, server_id: str, commit_sha: str) -> ScanReport:
    return ScanReport(findings=(), skipped=())


def _run(
    tmp_path: Path,
    index: Path,
    seen: list[str],
    *,
    sample: int | None = None,
    seed: int = DEFAULT_SAMPLE_SEED,
) -> PipelineResult:
    return run_index_scan(
        index_path=index,
        data_dir=tmp_path / "data",
        cache_dir=tmp_path / "cache",
        clone=_recording_clone(seen),
        scan=_no_findings,
        now=lambda: FIXED_NOW,
        sample=sample,
        seed=seed,
    )


def test_a_sample_reaches_the_orchestrator_rather_than_only_being_computed(
    tmp_path: Path,
) -> None:
    """Computing a subset and then scanning everything would look identical in
    the summary line, and would quietly spend two hours instead of ten
    minutes."""
    seen: list[str] = []

    _run(tmp_path, _index(tmp_path / "index.jsonl", 40), seen, sample=6)

    assert len(seen) == 6


def test_the_same_seed_scans_the_same_servers(tmp_path: Path) -> None:
    """The population the golden set is drawn from has to be nameable. If two
    runs of the same command scanned different servers, the published sampling
    method would describe a set nobody can rebuild."""
    index = _index(tmp_path / "index.jsonl", 40)
    first: list[str] = []
    second: list[str] = []

    _run(tmp_path / "a", index, first, sample=6, seed=99)
    _run(tmp_path / "b", index, second, sample=6, seed=99)

    assert sorted(first) == sorted(second)


def test_a_different_seed_scans_a_different_set(tmp_path: Path) -> None:
    index = _index(tmp_path / "index.jsonl", 40)
    first: list[str] = []
    second: list[str] = []

    _run(tmp_path / "a", index, first, sample=6, seed=1)
    _run(tmp_path / "b", index, second, sample=6, seed=2)

    assert sorted(first) != sorted(second)


def test_no_sample_scans_the_whole_index(tmp_path: Path) -> None:
    """The default has to stay the full corpus. A sampling flag that applied
    by accident would silently shrink every published figure."""
    seen: list[str] = []

    _run(tmp_path, _index(tmp_path / "index.jsonl", 12), seen)

    assert len(seen) == 12


def test_a_sample_larger_than_the_index_scans_everything(tmp_path: Path) -> None:
    """Asking for more than exists describes a smaller corpus, not an error,
    and must not raise on the day the corpus shrinks below the flag."""
    seen: list[str] = []

    _run(tmp_path, _index(tmp_path / "index.jsonl", 5), seen, sample=500)

    assert len(seen) == 5


def test_a_zero_sample_is_refused_as_a_sentence_rather_than_a_traceback(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Scanning nothing is indistinguishable from a broken crawl, and a
    traceback is not how this command reports anything else."""
    index = _index(tmp_path / "index.jsonl", 5)

    exit_code = main(
        [
            "scan",
            "--index",
            str(index),
            "--sample",
            "0",
            "--data-dir",
            str(tmp_path / "data"),
            "--cache-dir",
            str(tmp_path / "cache"),
        ]
    )

    assert exit_code == EXIT_SCAN_FAILED
    assert "positive" in capsys.readouterr().err
    assert "Traceback" not in capsys.readouterr().err


def test_sampling_a_single_repository_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """--sample only means anything against an index. Ignoring it silently
    would scan one server while the caller believed they had asked for a
    subset of many."""
    exit_code = main(
        ["scan", "--repo-url", "https://github.com/a/b", "--server-id", "a/b", "--sample", "5"]
    )

    assert exit_code == EXIT_SCAN_FAILED
    assert "--sample" in capsys.readouterr().err


def test_a_missing_server_id_is_refused_as_a_sentence_rather_than_a_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Ordinary user error. The message was already right and arrived as a
    traceback, because ValueError was not among the failures main reports."""
    exit_code = main(["scan", "--path", "."])

    assert exit_code == EXIT_SCAN_FAILED
    assert "--server-id" in capsys.readouterr().err
