"""Scan many servers, so that one bad repository cannot end the run."""

import shutil
import subprocess
import tempfile
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from analyzer.crawler.registry import ServerRecord
from analyzer.fetcher.clone import CloneResult, CloneTooLarge
from analyzer.models import Finding
from analyzer.scanner import ScanReport, SkippedFile

CloneFn = Callable[[str, Path], CloneResult]
ScanFn = Callable[[Path, str, str], ScanReport]

Status = Literal["scanned", "unreachable", "too-large", "failed"]

# A repository that is gone is a fact about that repository. A rule that
# raises is a defect in ours. Measured twice against the live corpus, 19% of
# 150 and 22% of 60 are deleted or private, so a run over the whole corpus
# produces thousands of these. Filed as failures, they would bury the handful
# of entries that mean something is actually broken.
#
# git reports it by exiting 128 and asking for a username: GitHub declines to
# say whether a private repository exists, so a deleted one and one we cannot
# see are indistinguishable from here, and both are equally unscannable.
UNREACHABLE_ERRORS = (
    subprocess.CalledProcessError,
    subprocess.TimeoutExpired,
    TimeoutError,
)

# Eight, from measurement rather than taste. Over 60 real repositories:
# sequential runs 58.4s and projects to 5.8 hours for the registry alone,
# against a six-hour job limit and before the 13,694 code-search candidates.
# Eight workers run the same set in 12.2s, about 1.2 hours projected. Sixteen
# manage 11.0s, which buys four minutes across a whole run while pushing the
# p90 for a single repository from 2.0s to 3.2s.
DEFAULT_WORKERS = 8


@dataclass(frozen=True)
class ScanOutcome:
    """What happened to one server, whether or not it worked.

    Every field is filled on every path, so a caller never has to know which
    status implies which absent value.
    """

    server_id: str
    status: Status
    findings: tuple[Finding, ...] = ()
    skipped: tuple[SkippedFile, ...] = ()
    commit_sha: str = ""
    error: str = ""


def scan_server(
    record: ServerRecord,
    *,
    clone: CloneFn,
    scan: ScanFn,
    workdir: Path,
) -> ScanOutcome:
    """Clone and scan one server. Never raises.

    Spec section 9's first requirement lives here: one repository failing to
    clone or parse must never fail the run. That is the difference between a
    21,000-server scan reporting 20,000 results and one reporting a traceback,
    and it is why the isolation is what gets tested while the happy path is
    almost incidental.

    The clone is removed whatever happens. The fetcher cleans up after its own
    failures but cannot touch the successful path, because those are the files
    the caller is reading, so ownership of that path belongs here. Over 35,000
    repositories a night, not removing them fills the disk.
    """
    dest = Path(tempfile.mkdtemp(dir=workdir))
    try:
        result = clone(record.repo_url, dest / "repo")
        report = scan(result.path, record.server_id, result.commit_sha)
        return ScanOutcome(
            server_id=record.server_id,
            status="scanned",
            findings=tuple(report.findings),
            skipped=tuple(report.skipped),
            commit_sha=result.commit_sha,
        )
    except CloneTooLarge as exc:
        return ScanOutcome(record.server_id, "too-large", error=str(exc))
    except UNREACHABLE_ERRORS as exc:
        return ScanOutcome(record.server_id, "unreachable", error=_describe(exc))
    except Exception as exc:  # noqa: BLE001 - isolation is the entire point
        # Deliberately broad, and deliberately not BaseException: a
        # KeyboardInterrupt or a SystemExit should still end the run, because
        # those are someone asking it to stop rather than a repository
        # misbehaving.
        return ScanOutcome(record.server_id, "failed", error=_describe(exc))
    finally:
        shutil.rmtree(dest, ignore_errors=True)


def _describe(exc: BaseException) -> str:
    """Name the exception type as well as its message.

    A bare message from a third-party library is often unattributable once it
    reaches a report over thousands of servers, and the type is the part that
    says whose problem it is.
    """
    return f"{type(exc).__name__}: {exc}"


def scan_all(
    records: Iterable[ServerRecord],
    *,
    clone: CloneFn,
    scan: ScanFn,
    workdir: Path,
    workers: int = DEFAULT_WORKERS,
) -> list[ScanOutcome]:
    """Scan every record concurrently, in input order.

    Order is the input's, never completion order. The output becomes a
    published document, and one that reordered itself according to which clone
    happened to finish first would produce a nightly diff full of churn that
    means nothing about the ecosystem.

    Threads rather than processes: the work is dominated by git waiting on the
    network, and every scan is a pure function over files on disk, so there is
    no state to share and nothing to pickle.
    """

    def run(record: ServerRecord) -> ScanOutcome:
        return scan_server(record, clone=clone, scan=scan, workdir=workdir)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        # map preserves input order regardless of completion order.
        return list(pool.map(run, records))
