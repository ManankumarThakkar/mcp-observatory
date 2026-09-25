"""The source window a finding is judged from, captured once for everyone."""

import shutil
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from analyzer.fetcher.clone import CloneTooLarge, FetchError
from analyzer.models import Finding
from analyzer.orchestrator import UNREACHABLE_ERRORS, CloneFn, ScanFn
from analyzer.scanner import ScanReport

# Exactly the failures that mean "this repository cannot be read", and nothing
# else. Deliberately not a blind `except Exception`: the orchestrator catches
# broadly because isolating one bad repository from a corpus run is its entire
# job, but here a ValueError out of a rule is a defect, and swallowing it into
# a dropped entry would hide it among the ordinary churn of an ecosystem where
# a fifth of repositories are already deleted or private.
UNREADABLE = (CloneTooLarge, FetchError, OSError, *UNREACHABLE_ERRORS)

# Twelve lines either side of the flagged line. Measured rather than chosen: a
# first integration that sent the flagged expression alone returned nearly the
# same probability for every input, and twelve lines either side more than
# doubled the spread. Below that a judgement carries no information; well above
# it the cost rises with no measured gain.
#
# The same window reaches the human labeller and every adjudicator. If they saw
# different amounts, the benchmark would be measuring context rather than
# judgement, and the difference it reported would be unattributable.
CONTEXT_LINES = 12


@dataclass(frozen=True)
class CaptureResult:
    """The windows captured, and every entry that could not be.

    Drops are returned rather than logged because the sampler publishes the
    shortfall. A golden set that quietly ended up smaller than it claims is a
    sample whose method no longer describes it.
    """

    contexts: dict[str, str] = field(default_factory=dict)
    dropped: dict[str, str] = field(default_factory=dict)


def capture_context(source: str, line: int, *, window: int = CONTEXT_LINES) -> str | None:
    """The `window` lines either side of a one-indexed line, or None.

    None means the line is past the end of the file, which happens because the
    clone is taken at the repository's current head and that may be many
    commits after the scan. A file that shrank is an ordinary fact about a
    moving ecosystem, so the entry is dropped rather than the run failing.

    A line below one is different and raises. Lines are one-indexed
    everywhere here, so a zero or negative one cannot come from a valid
    Location: it means a rule computed a line wrongly, and absorbing that into
    a dropped entry would hide a defect among ordinary churn.

    `splitlines` rather than `split("\\n")` so a file with carriage returns
    does not produce a window with a blank line between every line of code.
    """
    if line < 1:
        raise ValueError(f"lines are one-indexed, got {line}")

    lines = source.splitlines()
    if line > len(lines):
        return None

    # max() and min() rather than a bare slice. `line - window - 1` goes
    # negative near the top of a file, and a negative start silently returns
    # the tail instead of the head - an unrelated passage, presented to the
    # labeller as though it were the right one.
    start = max(0, line - window - 1)
    end = min(len(lines), line + window)
    return "\n".join(lines[start:end])


def capture_for_findings(
    findings: Iterable[Finding],
    *,
    repo_urls: Mapping[str, str],
    clone: CloneFn,
    scan: ScanFn,
    workdir: Path,
) -> CaptureResult:
    """Capture each finding's window from code that still produces that finding.

    The check is the reason this is not simply "read the file and slice it".
    The repository is cloned at its current head, which may be months after
    the scan that produced these findings, so the line a finding names may now
    hold entirely different code. Labelling that would put a verdict about
    code nobody flagged into the ground truth, and nothing downstream could
    detect the substitution.

    So each repository is re-scanned and a finding is kept only if the fresh
    scan produces the same `finding_id`. That identity is deterministic over
    server, rule, path, line and evidence, and deliberately excludes the
    commit, which makes it exactly the question worth asking: is this the same
    finding, in code that has possibly moved? Re-using it beats inventing a
    comparison, and beats matching on evidence, which is a description for
    some rules and normalised source for others.

    One clone and one scan per repository, not per finding. Failures are
    recorded against the findings they cost and the capture continues:
    meeting one deleted repository three hundred clones in must not discard
    the work already done.
    """
    by_server: dict[str, list[Finding]] = {}
    for finding in findings:
        by_server.setdefault(finding.server_id, []).append(finding)

    result = CaptureResult()
    for server_id, group in sorted(by_server.items()):
        if server_id not in repo_urls:
            # The urls come from the index these findings were scanned from,
            # so a missing one means the two went out of step. Dropping it
            # quietly would shrink the sample for a reason nobody could see.
            raise KeyError(f"no repository url for {server_id}")

        destination = workdir / server_id.replace("/", "_")
        try:
            cloned = clone(repo_urls[server_id], destination)
            report = scan(cloned.path, server_id, cloned.commit_sha)
            _capture_from(cloned.path, group, report, result)
        except UNREADABLE as exc:
            for finding in group:
                result.dropped[finding.finding_id] = f"{type(exc).__name__}: {exc}"
        finally:
            # Released before the next repository is fetched. Keeping them all
            # made peak disk the sum of every repository rather than the largest
            # single one, which filled a disk part-way through a re-draw. In
            # `finally`, because the failure path is the one that fills a disk:
            # it is the path taken by whatever is wrong with the repository.
            shutil.rmtree(destination, ignore_errors=True)

    return result


def _capture_from(
    root: Path,
    group: list[Finding],
    report: ScanReport,
    result: CaptureResult,
) -> None:
    """Take each finding's window from a clone that is about to be deleted."""
    still_found = {fresh.finding_id for fresh in report.findings}
    for finding in group:
        if finding.finding_id not in still_found:
            result.dropped[finding.finding_id] = (
                "the current code no longer produces this finding, so the window "
                "at this line is not the code that was flagged"
            )
            continue

        path = root / finding.location.file
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.dropped[finding.finding_id] = f"unreadable: {exc}"
            continue

        captured = capture_context(source, finding.location.line)
        if captured is None:
            result.dropped[finding.finding_id] = "line is past the end of the file"
            continue
        result.contexts[finding.finding_id] = captured

