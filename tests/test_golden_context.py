from pathlib import Path

import pytest

from analyzer.fetcher.clone import CloneResult
from analyzer.models import Finding, Location
from analyzer.orchestrator import CloneFn
from analyzer.scanner import ScanReport
from evals.golden.context import CONTEXT_LINES, capture_context, capture_for_findings

SOURCE = "\n".join(f"line {n}" for n in range(1, 51))


def test_the_window_is_centred_on_the_flagged_line() -> None:
    """The flagged line is the thing the reader is being asked about."""
    captured = capture_context(SOURCE, 25)

    assert captured is not None
    assert "line 25" in captured
    assert "line 13" in captured
    assert "line 37" in captured
    assert "line 12" not in captured
    assert "line 38" not in captured


def test_a_finding_near_the_top_does_not_wrap_to_the_end_of_the_file() -> None:
    """Line 2 has no twelve lines above it. `line - window - 1` goes negative,
    and a negative slice start silently returns the tail of the file rather
    than the head, handing the reader an unrelated passage with no sign of it.
    """
    captured = capture_context(SOURCE, 2)

    assert captured is not None
    assert captured.startswith("line 1")
    assert "line 50" not in captured


def test_a_finding_on_the_last_line_stops_at_the_end() -> None:
    captured = capture_context(SOURCE, 50)

    assert captured is not None
    assert captured.endswith("line 50")


def test_a_window_wider_than_the_file_returns_the_whole_file() -> None:
    captured = capture_context("a\nb\nc", 2)

    assert captured == "a\nb\nc"


def test_a_line_past_the_end_is_not_capturable_rather_than_an_error() -> None:
    """The repository is cloned at its current head, which may have moved
    since the scan. A file that shrank is an ordinary fact about an ecosystem
    that keeps moving, not a defect, so it is reported as uncapturable and
    the entry is dropped.
    """
    assert capture_context(SOURCE, 500) is None


def test_a_line_before_the_first_is_a_defect_and_is_loud() -> None:
    """Lines are one-indexed everywhere in this project. A zero or negative
    line cannot come from a valid Location, so it means a rule computed one
    wrongly, and that should not be quietly absorbed into a dropped entry.
    """
    with pytest.raises(ValueError, match="one-indexed"):
        capture_context(SOURCE, 0)


def test_windows_line_endings_do_not_produce_doubled_blank_lines() -> None:
    """A file with CRLF endings read as text keeps the carriage returns, and
    joining on newline afterwards would show the labeller a window with a
    blank line between every line of code.
    """
    captured = capture_context("a\r\nb\r\nc", 2)

    assert captured == "a\nb\nc"


def test_the_window_size_is_the_measured_one() -> None:
    """Twelve is a measured floor, not a preference: one flagged expression
    alone returned nearly the same probability for everything, and twelve
    lines either side more than doubled the spread. Moving it moves what the
    benchmark compares, so it has to be re-measured rather than nudged.
    """
    assert CONTEXT_LINES == 12


def _finding(server_id: str, file: str, line: int, evidence: str) -> Finding:
    return Finding(
        server_id=server_id,
        commit_sha="a" * 40,
        rule_id="SHELL-EXEC-UNSAFE",
        severity="critical",
        confidence="low",
        location=Location(file=file, line=line),
        evidence=evidence,
    )


def _clone_writing(source: str) -> CloneFn:
    def clone(repo_url: str, destination: Path) -> CloneResult:
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "index.ts").write_text(source, encoding="utf-8")
        return CloneResult(path=destination, commit_sha="b" * 40)

    return clone


def test_a_finding_the_fresh_scan_still_produces_gets_its_window(tmp_path: Path) -> None:
    """`finding_id` is deterministic over server, rule, path, line and
    evidence, and deliberately excludes the commit. So a fresh scan producing
    the same id is proof that the window about to be captured is the code
    that was flagged, not whatever now sits at that line number.
    """
    finding = _finding("a/one", "index.ts", 25, "exec(cmd)")

    result = capture_for_findings(
        [finding],
        repo_urls={"a/one": "https://github.com/a/one"},
        clone=_clone_writing(SOURCE),
        scan=lambda root, server_id, commit_sha: ScanReport(findings=(finding,), skipped=()),
        workdir=tmp_path,
    )

    assert finding.finding_id in result.contexts
    assert "line 25" in result.contexts[finding.finding_id]


def test_a_finding_the_code_no_longer_produces_is_dropped_with_a_reason(
    tmp_path: Path,
) -> None:
    """Without this the benchmark silently labels code that was never
    flagged. The clone is at the current head, which may be months of commits
    after the scan, and nothing else would notice the substitution.
    """
    finding = _finding("a/one", "index.ts", 25, "exec(cmd)")

    result = capture_for_findings(
        [finding],
        repo_urls={"a/one": "https://github.com/a/one"},
        clone=_clone_writing(SOURCE),
        scan=lambda root, server_id, commit_sha: ScanReport(findings=(), skipped=()),
        workdir=tmp_path,
    )

    assert finding.finding_id not in result.contexts
    assert "no longer" in result.dropped[finding.finding_id]


def test_one_repository_is_cloned_once_however_many_findings_it_has(
    tmp_path: Path,
) -> None:
    """A server with eight findings must not be cloned eight times."""
    findings = [_finding("a/one", "index.ts", line, "exec(cmd)") for line in (10, 20, 30)]
    clones: list[str] = []

    def counting_clone(repo_url: str, destination: Path) -> CloneResult:
        clones.append(repo_url)
        return _clone_writing(SOURCE)(repo_url, destination)

    capture_for_findings(
        findings,
        repo_urls={"a/one": "https://github.com/a/one"},
        clone=counting_clone,
        scan=lambda root, server_id, commit_sha: ScanReport(findings=tuple(findings), skipped=()),
        workdir=tmp_path,
    )

    assert len(clones) == 1


def test_an_unreachable_repository_drops_its_findings_without_ending_the_capture(
    tmp_path: Path,
) -> None:
    """Capturing three hundred entries across as many repositories will meet
    a deleted or renamed one. Ending the run there would waste every clone
    already made.
    """
    from analyzer.fetcher.clone import FetchError

    gone = _finding("a/gone", "index.ts", 25, "exec(cmd)")
    fine = _finding("b/fine", "index.ts", 25, "exec(cmd)")

    def clone(repo_url: str, destination: Path) -> CloneResult:
        if "gone" in repo_url:
            raise FetchError("repository not found")
        return _clone_writing(SOURCE)(repo_url, destination)

    result = capture_for_findings(
        [gone, fine],
        repo_urls={"a/gone": "https://github.com/a/gone", "b/fine": "https://github.com/b/fine"},
        clone=clone,
        scan=lambda root, server_id, commit_sha: ScanReport(
            findings=(gone, fine), skipped=()
        ),
        workdir=tmp_path,
    )

    assert fine.finding_id in result.contexts
    assert "not found" in result.dropped[gone.finding_id]


def test_a_finding_whose_repository_url_is_unknown_is_a_defect(tmp_path: Path) -> None:
    """The urls come from the same index the findings were scanned from, so a
    missing one means the two went out of step. Dropping it silently would
    shrink the sample for a reason nobody could see.
    """
    finding = _finding("a/one", "index.ts", 25, "exec(cmd)")

    with pytest.raises(KeyError, match="a/one"):
        capture_for_findings(
            [finding],
            repo_urls={},
            clone=_clone_writing(SOURCE),
            scan=lambda root, server_id, commit_sha: ScanReport(findings=(finding,), skipped=()),
            workdir=tmp_path,
        )


def test_each_clone_is_released_before_the_next_is_fetched(tmp_path: Path) -> None:
    """The capture clones one repository per affected server - about 140 for a
    300-entry set - and kept every one until the whole run finished. Peak disk
    was the sum of every repository rather than the largest single one, which
    is how a re-draw filled a disk and died part-way through.

    A shallow clone is capped at 50 MB, so the accumulated worst case is
    measured in gigabytes while the necessary worst case is 50 MB.
    """
    findings = [_finding(f"srv/{n}", "index.ts", 25, "exec(cmd)") for n in range(3)]
    urls = {f.server_id: f"https://github.com/{f.server_id}" for f in findings}
    peak = 0

    def clone(repo_url: str, destination: Path) -> CloneResult:
        nonlocal peak
        result = _clone_writing(SOURCE)(repo_url, destination)
        peak = max(peak, sum(1 for _ in tmp_path.rglob("index.ts")))
        return result

    capture_for_findings(
        findings,
        repo_urls=urls,
        clone=clone,
        scan=lambda root, server_id, commit_sha: ScanReport(
            findings=tuple(f for f in findings if f.server_id == server_id), skipped=()
        ),
        workdir=tmp_path,
    )

    assert peak == 1, f"{peak} clones were on disk at once; each should be released"


def test_a_clone_is_released_even_when_its_scan_fails(tmp_path: Path) -> None:
    """The failure path is the one that fills a disk, because it is the path
    taken by whatever is wrong with the repository."""
    finding = _finding("a/one", "index.ts", 25, "exec(cmd)")

    def failing_scan(root: Path, server_id: str, commit_sha: str) -> ScanReport:
        raise OSError("scan blew up")

    capture_for_findings(
        [finding],
        repo_urls={"a/one": "https://github.com/a/one"},
        clone=_clone_writing(SOURCE),
        scan=failing_scan,
        workdir=tmp_path,
    )

    assert list(tmp_path.rglob("index.ts")) == []
