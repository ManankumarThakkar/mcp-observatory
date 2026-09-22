import subprocess
import time
from pathlib import Path

from analyzer.crawler.registry import ServerRecord
from analyzer.fetcher.clone import CloneResult, CloneTooLarge
from analyzer.models import Finding, Location
from analyzer.orchestrator import ScanOutcome, scan_all, scan_server
from analyzer.scanner import ScanReport, SkippedFile


def _record(server_id: str = "acme/thing") -> ServerRecord:
    return ServerRecord(
        server_id=server_id,
        repo_url=f"https://github.com/{server_id}",
        discovered_via="registry",
    )


def _finding(server_id: str) -> Finding:
    return Finding(
        server_id=server_id,
        commit_sha="a" * 40,
        rule_id="UNICODE-CONCEAL",
        severity="critical",
        confidence="high",
        location=Location(file="src/server.py", line=1),
        evidence="unicode-tag-block U+E0041 at line 1",
    )


def _clone_ok(url: str, dest: Path) -> CloneResult:
    dest.mkdir(parents=True, exist_ok=True)
    return CloneResult(path=dest, commit_sha="a" * 40)


def _scan_ok(root: Path, server_id: str, commit_sha: str) -> ScanReport:
    return ScanReport(findings=(_finding(server_id),), skipped=())


def test_a_successful_scan_records_its_findings_and_commit(tmp_path: Path) -> None:
    outcome = scan_server(_record(), clone=_clone_ok, scan=_scan_ok, workdir=tmp_path)

    assert outcome.status == "scanned"
    assert outcome.commit_sha == "a" * 40
    assert len(outcome.findings) == 1


def test_one_exploding_server_does_not_stop_the_others(tmp_path: Path) -> None:
    """Spec section 9's first requirement, and the reason this module exists.

    The difference between a 21,000-server run that reports 20,000 results and
    one that reports a traceback.
    """

    def clone(url: str, dest: Path) -> CloneResult:
        if "boom" in url:
            raise RuntimeError("git exploded")
        return _clone_ok(url, dest)

    outcomes = scan_all(
        [_record("acme/one"), _record("acme/boom"), _record("acme/two")],
        clone=clone,
        scan=_scan_ok,
        workdir=tmp_path,
    )

    assert [o.status for o in outcomes] == ["scanned", "failed", "scanned"]
    assert "git exploded" in outcomes[1].error
    assert outcomes[1].findings == ()


def test_a_rule_that_raises_is_isolated_too(tmp_path: Path) -> None:
    """A crash in our own code is the likelier failure once parsers arrive."""

    def scan(root: Path, server_id: str, commit_sha: str) -> ScanReport:
        raise ValueError("rule blew up")

    outcome = scan_server(_record(), clone=_clone_ok, scan=scan, workdir=tmp_path)

    assert outcome.status == "failed"
    assert "rule blew up" in outcome.error


def test_a_repository_that_no_longer_exists_is_not_called_a_failure(
    tmp_path: Path,
) -> None:
    """22% of the corpus is deleted or private, measured twice.

    Lumping those in with genuine failures produces roughly 4,700 entries a
    night that all mean the same harmless thing, and a real crash in a rule
    would sit invisible among them. A repository that is gone is a fact about
    that repository; a rule that raises is a defect in ours.
    """

    def clone(url: str, dest: Path) -> CloneResult:
        # What a deleted or private repository actually produces, measured
        # against the live corpus: git exits 128 asking for a username,
        # because GitHub will not say whether a private repository exists.
        raise subprocess.CalledProcessError(128, ["git", "clone"], stderr="not found")

    outcome = scan_server(_record(), clone=clone, scan=_scan_ok, workdir=tmp_path)

    assert outcome.status == "unreachable"


def test_a_repository_over_the_caps_has_its_own_status(tmp_path: Path) -> None:
    def clone(url: str, dest: Path) -> CloneResult:
        raise CloneTooLarge("repository exceeds 50 MB")

    outcome = scan_server(_record(), clone=clone, scan=_scan_ok, workdir=tmp_path)

    assert outcome.status == "too-large"


def test_the_clone_is_removed_whatever_happens(tmp_path: Path) -> None:
    """A nightly run over 35,000 repositories would otherwise fill the disk.

    The fetcher cleans up after its own failures, but cannot touch the
    successful path, because that is the path whose files the caller reads.
    """
    kept: list[Path] = []

    def clone(url: str, dest: Path) -> CloneResult:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "server.py").write_text("print('hi')\n", encoding="utf-8")
        kept.append(dest)
        return CloneResult(path=dest, commit_sha="a" * 40)

    scan_server(_record(), clone=clone, scan=_scan_ok, workdir=tmp_path)

    assert kept and not kept[0].exists()
    assert list(tmp_path.iterdir()) == []


def test_skipped_files_travel_with_the_outcome(tmp_path: Path) -> None:
    def scan(root: Path, server_id: str, commit_sha: str) -> ScanReport:
        return ScanReport(findings=(), skipped=(SkippedFile("big.py", "too-large"),))

    outcome = scan_server(_record(), clone=_clone_ok, scan=scan, workdir=tmp_path)

    assert outcome.skipped == (SkippedFile("big.py", "too-large"),)


def test_outcomes_keep_input_order_however_the_workers_finish(tmp_path: Path) -> None:
    """A published document must not depend on which clone happened to win.

    Without this the nightly diff churns on scheduling noise and stops meaning
    that the ecosystem moved.
    """

    def clone(url: str, dest: Path) -> CloneResult:
        # The first record sleeps longest, so completion order is the reverse
        # of input order and an unordered implementation cannot pass.
        time.sleep(0.05 if url.endswith("first") else 0.0)
        return _clone_ok(url, dest)

    records = [_record("acme/first"), _record("acme/second"), _record("acme/third")]

    outcomes = scan_all(records, clone=clone, scan=_scan_ok, workdir=tmp_path, workers=3)

    assert [o.server_id for o in outcomes] == ["acme/first", "acme/second", "acme/third"]


def test_work_actually_runs_in_parallel(tmp_path: Path) -> None:
    """Eight workers is the difference between 1.2 hours and 5.8.

    Measured over 60 real repositories: sequential projects to 5.8 hours for
    the registry alone, against a six-hour job limit, and that is before the
    13,694 code-search candidates. A pool that silently ran serially would
    still pass every other test here.
    """

    def clone(url: str, dest: Path) -> CloneResult:
        time.sleep(0.1)
        return _clone_ok(url, dest)

    records = [_record(f"acme/{n}") for n in range(8)]

    started = time.monotonic()
    scan_all(records, clone=clone, scan=_scan_ok, workdir=tmp_path, workers=8)
    elapsed = time.monotonic() - started

    assert elapsed < 0.4, f"8 x 0.1s took {elapsed:.2f}s, so it ran serially"


def test_scan_all_survives_a_record_whose_clone_hangs_forever(tmp_path: Path) -> None:
    """Nothing here may depend on the fetcher's own timeout to terminate."""

    def clone(url: str, dest: Path) -> CloneResult:
        if "slow" in url:
            raise TimeoutError("git timed out")
        return _clone_ok(url, dest)

    outcomes = scan_all(
        [_record("acme/slow"), _record("acme/fine")],
        clone=clone,
        scan=_scan_ok,
        workdir=tmp_path,
    )

    assert outcomes[0].status == "unreachable"
    assert outcomes[1].status == "scanned"


def test_every_outcome_carries_every_field(tmp_path: Path) -> None:
    """A caller must never need to know which status implies which absent value.

    A failure that left findings unset rather than empty would make every
    consumer guard against None before counting, and the one that forgot would
    crash on the rarest path.
    """

    def clone(url: str, dest: Path) -> CloneResult:
        raise RuntimeError("nope")

    outcome = scan_server(_record(), clone=clone, scan=_scan_ok, workdir=tmp_path)

    assert outcome == ScanOutcome(
        server_id="acme/thing",
        status="failed",
        findings=(),
        skipped=(),
        commit_sha="",
        error="RuntimeError: nope",
    )
