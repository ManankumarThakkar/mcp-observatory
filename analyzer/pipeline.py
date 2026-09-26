"""The nightly run: crawl output in, published findings out."""

import json
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
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

# The repository behind each server that has something published. Findings
# carry a server_id, which is a registry name and need not resemble the
# repository: one published as `com.arcandledger/tax-tools` lives at a GitHub
# path nobody would guess. A maintainer recognises their repository, so the id
# alone makes their own finding hard for them to identify.
#
# Only servers with published findings appear. Listing one whose findings are
# all withheld would name it in public output while the gate is holding those
# findings back.
SERVERS_FILE = "servers.json"

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
class Intake:
    """How the scanned set was chosen, so the published figures have a denominator.

    A page stating "1,643 servers scanned" invites exactly one question, and
    without this the published data cannot answer it. The chain is corpus,
    then sampled, then scanned, then skipped and failed, and each step is a
    number a reader can check against the one before it.

    `sampled` and `seed` are None for a full-corpus scan rather than equal to
    the corpus. "We sampled 21,492 of 21,492" invites a reader to look for a
    sampling method that was not used; the absence is the honest statement.
    """

    corpus: int
    sampled: int | None = None
    seed: int | None = None


@dataclass(frozen=True)
class PipelineResult:
    """What one run did, for the caller and for the summary file."""

    scanned: int
    skipped: int
    failed: int
    published: int
    withheld: int


def _previous_coverage(summary_path: Path) -> int | None:
    """The scanned count from a previous run, or None if there is not one.

    Distinct from `_previous_scanned`, which returns zero for "no previous
    run" because the collapse guard treats absence as nothing to compare
    against. Here absence must be refused rather than treated as zero, so the
    two cases cannot share a return value.
    """
    if not summary_path.exists():
        return None
    try:
        payload = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    scanned = payload.get("scanned")
    return scanned if isinstance(scanned, int) else None


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
    intake: Intake,
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
    # Materialised because it is an Iterable and is read twice: once by the
    # scan and once to name the repositories of whatever gets published. A
    # generator would scan normally and then publish an empty server list.
    records = list(records)
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

    published_count, counts = _publish(
        merged,
        data_dir=data_dir,
        disclosure_records=disclosure_records,
        now=now,
        tool_version=tool_version,
    )
    _write_servers(
        data_dir / SERVERS_FILE,
        {record.server_id: record.repo_url for record in records},
        data_dir / FINDINGS_FILE,
    )

    result = PipelineResult(
        scanned=scanned,
        skipped=skipped,
        failed=failed,
        published=published_count,
        withheld=counts["withheld"] + counts["opted_out"],
    )
    _write_summary(summary_path, result, counts, stamp, tool_version, intake, merged)
    return result


def _write_servers(path: Path, repo_urls: Mapping[str, str], findings_path: Path) -> None:
    """Name the repository behind every server that has something published.

    Read back from the file just written rather than from the gate's return
    value, so this cannot list a server the gate withheld: the published file
    is the definition of what is public, and deriving the list from anything
    else is a second definition that could disagree with it.
    """
    published = {
        json.loads(line)["server_id"]
        for line in findings_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            [
                {"server_id": server_id, "repo_url": repo_urls[server_id]}
                for server_id in sorted(published)
                if server_id in repo_urls
            ],
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _publish(
    merged: Sequence[Mapping[str, Any]],
    *,
    data_dir: Path,
    disclosure_records: Mapping[str, DisclosureRecord],
    now: datetime,
    tool_version: str,
) -> tuple[int, Mapping[str, int]]:
    """Write the publishable findings and the SARIF beside them.

    Shared by the scan pipeline and by republication, so there is exactly one
    route past the disclosure gate. Two implementations of "what may be
    published" would drift, and the drift would surface as findings reaching
    a public directory by the path nobody was checking.

    The gate runs over the whole history rather than one night's findings, so a
    finding withheld last month is published when its window closes rather
    than waiting to be seen again.
    """
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
    return len(published), counts


@dataclass(frozen=True)
class PublishResult:
    """What one republication released, and what it held back."""

    published: int
    withheld: int


def publish_from_history(
    *,
    cache_dir: Path,
    data_dir: Path,
    disclosure_records: Mapping[str, DisclosureRecord],
    now: datetime,
    tool_version: str,
    destination: Path | None = None,
) -> PublishResult:
    """Publish what the gate allows, from the history alone.

    Scanning and publishing are separate concerns and coupling them was wrong
    in two ways. Republishing required a full rescan of twenty-one thousand
    repositories, which is thirteen minutes and a network to change nothing but
    a date. And a disclosure window closing had no effect until a scan
    succeeded, so a run stopped by the collapse guard also held back every
    finding whose ninety days had elapsed - the gate failing closed for a
    reason that had nothing to do with disclosure.

    The gate itself is unchanged and shared: this is a second caller, never a
    second rule.

    A missing history raises rather than publishing nothing. Writing an empty
    `data/` would replace a good publication with silence and read as an
    ecosystem that fixed itself overnight.

    `destination` separates where the result is written from where the current
    publication is read, and exists because the two differ for a dry run. That
    distinction was missing and it broke the dry run completely: it pointed the
    destination at a throwaway directory so that the report would come from the
    real code path rather than a second implementation, which is right, but
    coverage is read from the same directory and a throwaway one has none. Every
    dry run therefore raised. It defaults to `data_dir`, so an ordinary
    publication still names one directory.
    """
    history_path = cache_dir / HISTORY_FILE
    if not history_path.exists():
        raise FileNotFoundError(
            f"no history at {history_path}; there is nothing to publish without a scan"
        )

    # Read from the current publication, written to wherever the caller says.
    summary_path = data_dir / SUMMARY_FILE
    write_dir = destination if destination is not None else data_dir
    coverage = _previous_coverage(summary_path)
    if coverage is None:
        # The history records findings, not how many servers were scanned: 306
        # of 1,642 produced anything. So a republication cannot know the
        # denominator, and a summary without it publishes findings with no
        # coverage figure - which is the one number success criterion 1 is
        # about, and the one a reader uses to judge how current the results
        # are. Scanning is the only thing that can establish it.
        raise ValueError(
            f"{summary_path} carries no scanned count, so coverage cannot be "
            "republished; run a scan instead"
        )

    merged = load_previous(history_path)
    published, counts = _publish(
        merged,
        data_dir=write_dir,
        disclosure_records=disclosure_records,
        now=now,
        tool_version=tool_version,
    )
    _stamp_publication(
        summary_path,
        write_dir / SUMMARY_FILE,
        counts,
        utc_stamp(now),
        tool_version,
        merged,
    )
    return PublishResult(published=published, withheld=counts["withheld"] + counts["opted_out"])


def _stamp_publication(
    source: Path,
    target: Path,
    counts: Mapping[str, int],
    stamp: str,
    tool_version: str,
    merged: Sequence[Mapping[str, Any]],
) -> None:
    """Update the disclosure counts and date the publication, keeping the scan.

    Read from `source` and written to `target`, which are the same path for an
    ordinary publication and differ for a dry run. The scan block being carried
    across is the reason the two cannot simply be one: it exists only in the
    current publication.

    The coverage figures describe the scan that produced them, and nothing was
    scanned here. Overwriting `generated_at` would date a 1,642-server scan to
    a day on which nothing was scanned, and a reader comparing the two would be
    wrong about when the corpus was examined. So the scan block is preserved
    and `published_at` is added beside it; equal values mean one operation did
    both.
    """
    payload: dict[str, Any] = {}
    if source.exists():
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            payload = {}

    payload.update(
        {
            "published_at": stamp,
            "tool_version": tool_version,
            "disclosure": dict(counts),
            # Recomputed here as well as in a scan, so a republication after a
            # window closes keeps the per-rule totals current rather than
            # leaving the dashboard describing an older run.
            "found_by_rule": dict(
                sorted(Counter(str(record["rule_id"]) for record in merged).items())
            ),
        }
    )
    # generated_at is deliberately never defaulted to now. It describes the
    # scan, and republication scans nothing; the caller has already refused to
    # proceed without a prior summary, so it is always present here.
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_summary(
    path: Path,
    result: PipelineResult,
    counts: Mapping[str, int],
    stamp: str,
    tool_version: str,
    intake: Intake,
    merged: Sequence[Mapping[str, Any]],
) -> None:
    """Publish the numbers even when the findings behind them are withheld.

    Spec section 11 publishes aggregate statistics immediately, so the index
    can say "41 critical findings withheld pending disclosure" without naming
    a single server.
    """
    payload: dict[str, Any] = {
        "generated_at": stamp,
        "tool_version": tool_version,
        # The denominator, and how the scanned set was chosen from it.
        "corpus": intake.corpus,
        "sampled": intake.sampled,
        "sample_seed": intake.seed,
        "scanned": result.scanned,
        "skipped": result.skipped,
        "failed": result.failed,
        "disclosure": dict(counts),
        # How many findings each rule produced, published or not. Aggregate and
        # non-attributable, which is the category SECURITY.md publishes
        # immediately - and without it the dashboard's per-rule table is four
        # rows of zeros, which reads as a scanner that finds nothing rather than
        # one whose findings are being withheld in full.
        "found_by_rule": dict(
            sorted(Counter(str(record["rule_id"]) for record in merged).items())
        ),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
