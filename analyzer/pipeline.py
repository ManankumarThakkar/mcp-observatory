"""The nightly run: crawl output in, published findings out."""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from analyzer.crawler.registry import ServerRecord
from analyzer.models import Finding
from analyzer.orchestrator import CloneFn, ScanFn, ValidateFn, scan_all
from analyzer.report.gate import DisclosureRecord, disclosure_state, split_for_publication
from analyzer.report.merge import (
    load_previous,
    merge_findings,
    utc_stamp,
    write_findings,
)
from analyzer.report.sarif import to_sarif
from analyzer.validation import looks_like_server

# What a run publishes, and where.
FINDINGS_FILE = "findings.jsonl"
SARIF_FILE = "findings.sarif"
SUMMARY_FILE = "summary.json"

# The full history, including findings the gate is withholding. Not published,
# because the directory above is committed to a public repository and a
# withheld finding written there is a disclosed one.
#
# It has to exist somewhere, though: the window is ninety days, and a record
# that vanished while withheld and returned on disclosure would reset its
# first_seen and show a gap in the trend that never happened.
HISTORY_FILE = "history.jsonl"

# A run that scanned far fewer servers than the last one is a broken upstream,
# not an ecosystem that shrank overnight. A parser cannot tell one odd record
# from a systemic break; this can, because it has last night's number.
#
# Half is deliberately loose. Servers do disappear, and the guard is for
# collapse rather than for ordinary drift, so it should fire on a crawl that
# returned almost nothing and stay quiet on one that lost a few percent.
COLLAPSE_RATIO = 0.5


class CollapsedRun(Exception):
    """Raised when a run covered too little of the corpus to publish."""


@dataclass(frozen=True)
class PipelineResult:
    """What one run did, for the caller and for the summary file."""

    scanned: int
    skipped: int
    failed: int
    published: int
    withheld: int


def _previous_scanned(summary_path: Path) -> int:
    """How many servers last night's run covered, or zero if there was none."""
    if not summary_path.exists():
        return 0
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        # An unreadable summary is not evidence of a healthy previous run, and
        # refusing to publish on that basis would be worse than proceeding:
        # the history is intact either way.
        return 0
    scanned = payload.get("scanned", 0)
    return scanned if isinstance(scanned, int) else 0


def run_pipeline(
    records: Iterable[ServerRecord],
    *,
    clone: CloneFn,
    scan: ScanFn,
    workdir: Path,
    data_dir: Path,
    cache_dir: Path,
    disclosure_records: Mapping[str, DisclosureRecord],
    now: datetime,
    tool_version: str,
    validate: ValidateFn = looks_like_server,
    collapse_ratio: float = COLLAPSE_RATIO,
) -> PipelineResult:
    """Scan every server, fold the results into the history, publish what may be.

    **Merge happens before the gate, never after.** Merging maintains
    first_seen and last_seen for every finding including withheld ones,
    because the series has to stay continuous across the ninety-day window.
    The gate then decides which of those merged records leave for publication.
    Invert the two and either the trend breaks or withheld findings leak.

    Only findings from servers that passed validation are recorded at all. A
    code-search candidate that could not prove it implements a server
    contributes nothing, which is the gate from Task 3 holding all the way to
    publication rather than only at the point it was checked.
    """
    # The orchestrator makes one temporary directory per server inside this
    # one, so it has to exist before the first worker starts. Creating it here
    # rather than requiring the caller to means a fresh checkout runs.
    workdir.mkdir(parents=True, exist_ok=True)
    outcomes = scan_all(
        records, clone=clone, scan=scan, workdir=workdir, validate=validate
    )

    scanned = sum(1 for outcome in outcomes if outcome.status == "scanned")
    failed = sum(1 for outcome in outcomes if outcome.status == "failed")
    skipped = len(outcomes) - scanned - failed

    summary_path = data_dir / SUMMARY_FILE
    previous_scanned = _previous_scanned(summary_path)
    if previous_scanned and scanned < previous_scanned * collapse_ratio:
        # Raised before anything is written, so the previous publication
        # survives intact. A run this short is a broken crawl, and publishing
        # it would read as an ecosystem that fixed itself overnight.
        raise CollapsedRun(
            f"scanned {scanned} servers against {previous_scanned} last run; "
            "refusing to publish a run that covered so much less of the corpus"
        )

    stamp = utc_stamp(now)
    history_path = cache_dir / HISTORY_FILE
    current = [
        finding.to_dict()
        for outcome in outcomes
        if outcome.admitted
        for finding in outcome.findings
    ]
    merged = merge_findings(load_previous(history_path), current, now=stamp)
    write_findings(history_path, merged)

    # The gate runs over the whole merged history rather than tonight's
    # findings alone, so a finding withheld last month is published the night
    # its window closes rather than waiting to be seen again.
    findings = [Finding.from_dict(record) for record in merged]
    published, counts = split_for_publication(findings, disclosure_records, now=now)
    publishable = {finding.finding_id for finding in published}

    write_findings(
        data_dir / FINDINGS_FILE,
        [
            {
                **record,
                "disclosure_state": disclosure_state(
                    Finding.from_dict(record),
                    disclosure_records.get(record["server_id"]),
                    now=now,
                ),
            }
            for record in merged
            if record["finding_id"] in publishable
        ],
    )

    (data_dir / SARIF_FILE).write_text(
        json.dumps(to_sarif(published, tool_version=tool_version), indent=2) + "\n",
        encoding="utf-8",
    )

    result = PipelineResult(
        scanned=scanned,
        skipped=skipped,
        failed=failed,
        published=len(published),
        withheld=counts["withheld"] + counts["opted_out"],
    )
    _write_summary(summary_path, result, counts, stamp, tool_version)
    return result


def _write_summary(
    path: Path,
    result: PipelineResult,
    counts: Mapping[str, int],
    stamp: str,
    tool_version: str,
) -> None:
    """Publish the numbers even when the findings behind them are withheld.

    Spec section 11 publishes aggregate statistics immediately, so the index
    can say "41 critical findings withheld pending disclosure" without naming
    a single server.
    """
    payload: dict[str, Any] = {
        "generated_at": stamp,
        "tool_version": tool_version,
        "scanned": result.scanned,
        "skipped": result.skipped,
        "failed": result.failed,
        "disclosure": dict(counts),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
