import json
from pathlib import Path
from typing import Any

import pytest

from analyzer.models import Finding, Location
from analyzer.report.merge import load_previous, merge_findings, write_findings

NOW = "2026-09-20T00:00:00Z"
EARLIER = "2026-08-01T00:00:00Z"


def _finding(rule_id: str = "UNICODE-CONCEAL", line: int = 42, sha: str = "a" * 40) -> Finding:
    return Finding(
        server_id="owner/repo",
        commit_sha=sha,
        rule_id=rule_id,
        severity="critical",
        confidence="high",
        location=Location(file="src/index.ts", line=line),
        evidence=f"unicode-tag-block U+E0041 at line {line}",
    )


def _aged(finding: Finding, first: str = EARLIER, last: str = EARLIER) -> dict[str, Any]:
    return {**finding.to_dict(), "first_seen": first, "last_seen": last}


# --- the time series ----------------------------------------------------------

def test_a_brand_new_finding_gets_both_timestamps() -> None:
    merged = merge_findings([], [_finding().to_dict()], now=NOW)

    assert len(merged) == 1
    assert merged[0]["first_seen"] == NOW
    assert merged[0]["last_seen"] == NOW


def test_seeing_a_finding_again_advances_only_last_seen() -> None:
    """This is what makes a trend possible at all.

    `finding_id` excludes commit_sha precisely so the same issue across
    nightly runs is one record whose last_seen moves, rather than a new
    record every night.
    """
    previous = [_aged(_finding())]

    merged = merge_findings(previous, [_finding().to_dict()], now=NOW)

    assert len(merged) == 1
    assert merged[0]["first_seen"] == EARLIER
    assert merged[0]["last_seen"] == NOW


def test_a_finding_absent_tonight_is_kept_with_its_old_timestamp() -> None:
    """Spec section 9's partial-run tolerance, and the property that matters most.

    A run covering 60% of the corpus must update 60% and leave the rest
    alone. If a rate limit stops the crawler halfway, the missing 40% are
    unknown tonight, not resolved tonight. Deleting them would rewrite
    history and make the published trend a lie.
    """
    previous = [_aged(_finding(line=1)), _aged(_finding(line=2))]

    merged = merge_findings(previous, [_finding(line=1).to_dict()], now=NOW)

    by_line = {record["location"]["line"]: record for record in merged}
    assert by_line[1]["last_seen"] == NOW
    assert by_line[2]["last_seen"] == EARLIER, "an unscanned finding is not a fixed one"


def test_a_run_that_found_nothing_deletes_nothing() -> None:
    """The degenerate case of the same rule: a crawl that failed is not a clean bill."""
    previous = [_aged(_finding(line=1)), _aged(_finding(line=2))]

    merged = merge_findings(previous, [], now=NOW)

    assert len(merged) == 2
    assert all(record["last_seen"] == EARLIER for record in merged)


def test_the_commit_is_updated_when_a_finding_is_seen_again() -> None:
    """The finding is the same; the commit it was last seen at is not."""
    previous = [_aged(_finding(sha="a" * 40))]

    merged = merge_findings(previous, [_finding(sha="b" * 40).to_dict()], now=NOW)

    assert merged[0]["commit_sha"] == "b" * 40


def test_the_output_order_is_stable_across_runs() -> None:
    """A committed file must not churn because a scan finished in a new order."""
    findings = [_finding(line=n).to_dict() for n in (3, 1, 2)]

    first = merge_findings([], findings, now=NOW)
    second = merge_findings([], list(reversed(findings)), now=NOW)

    assert [r["finding_id"] for r in first] == [r["finding_id"] for r in second]


# --- refusing to corrupt the history -----------------------------------------

def test_a_local_scan_cannot_enter_the_history() -> None:
    """`--path` labels findings commit_sha="local".

    Because finding_id excludes commit_sha, such a record shares an identity
    with a real finding, so merging one would overwrite a genuine record with
    a commit that does not exist. One check at the boundary beats a convention
    every producer has to remember.
    """
    local = _finding(sha="local").to_dict()

    with pytest.raises(ValueError, match="commit_sha"):
        merge_findings([], [local], now=NOW)


@pytest.mark.parametrize("sha", ["", "abc", "z" * 40, "A" * 41, "a" * 39])
def test_only_a_full_commit_hash_is_accepted(sha: str) -> None:
    with pytest.raises(ValueError, match="commit_sha"):
        merge_findings([], [_finding(sha=sha).to_dict()], now=NOW)


def test_an_uppercase_hash_is_accepted() -> None:
    """Git accepts either case and some tools emit uppercase."""
    merged = merge_findings([], [_finding(sha="A" * 40).to_dict()], now=NOW)

    assert len(merged) == 1


def test_a_previous_record_missing_its_timestamps_is_repaired_not_dropped() -> None:
    """A record written before this format existed still counts as seen."""
    stale = _finding().to_dict()

    merged = merge_findings([stale], [], now=NOW)

    assert merged[0]["first_seen"] == NOW
    assert merged[0]["last_seen"] == NOW


# --- the file on disk ---------------------------------------------------------

def test_records_round_trip_through_the_file(tmp_path: Path) -> None:
    records = merge_findings([], [_finding().to_dict()], now=NOW)
    path = tmp_path / "nested" / "findings.jsonl"

    write_findings(path, records)

    assert load_previous(path) == records


def test_a_missing_file_is_an_empty_history(tmp_path: Path) -> None:
    """The first run has no previous file and must not be a special case."""
    assert load_previous(tmp_path / "absent.jsonl") == []


def test_a_corrupt_history_stops_the_run(tmp_path: Path) -> None:
    """Skipping a bad line would silently shorten the published history.

    A run that fails loudly can be fixed. A run that quietly drops a record
    publishes a trend with a hole in it that nobody can see.
    """
    path = tmp_path / "findings.jsonl"
    path.write_text('{"finding_id": "a"}\nnot json at all\n', encoding="utf-8")

    with pytest.raises(ValueError, match="line 2"):
        load_previous(path)


def test_the_file_is_one_json_object_per_line(tmp_path: Path) -> None:
    records = merge_findings(
        [], [_finding(line=1).to_dict(), _finding(line=2).to_dict()], now=NOW
    )
    path = tmp_path / "findings.jsonl"

    write_findings(path, records)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert all(json.loads(line) for line in lines)
