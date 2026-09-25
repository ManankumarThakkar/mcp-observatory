import json
from pathlib import Path

import pytest

from analyzer.report.site import build_site_data, write_site_data


def _published(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "finding_id": "f1",
        "server_id": "acme/one",
        "commit_sha": "a" * 40,
        "rule_id": "SCOPE-OVERBROAD",
        "severity": "medium",
        "confidence": "low",
        "location": {"file": "src/index.ts", "line": 10},
        "evidence": "accepts any origin (*)",
        "first_seen": "2026-09-23T00:00:00Z",
        "last_seen": "2026-09-25T00:00:00Z",
        "disclosure_state": "published",
    }
    row.update(overrides)
    return row


SUMMARY = {
    "generated_at": "2026-09-25T01:10:58Z",
    "published_at": "2026-09-25T01:12:00Z",
    "tool_version": "0.1.0",
    "scanned": 1643,
    "skipped": 357,
    "failed": 0,
    "disclosure": {"published": 322, "withheld": 963, "disclosed": 0, "opted_out": 0},
}


def _write(tmp_path: Path, rows: list[dict[str, object]], summary: dict[str, object] | None = None) -> Path:
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "findings.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
    )
    (data / "summary.json").write_text(json.dumps(summary or SUMMARY), encoding="utf-8")
    return data


def test_repeated_findings_of_one_decision_are_grouped(tmp_path: Path) -> None:
    """A server that sets a wildcard origin sets it on every response path.
    Measured on the real published set: 322 rows are 164 decisions, and one
    server contributes 16 rows for a single misconfiguration. A reader counting
    rows would take one decision for sixteen problems.
    """
    rows = [
        _published(finding_id=f"f{n}", location={"file": "src/index.ts", "line": n})
        for n in range(16)
    ]

    site = build_site_data(_write(tmp_path, rows))

    assert site.findings_total == 16
    assert site.decisions_total == 1
    assert site.groups[0].occurrences == 16


def test_the_raw_count_is_kept_beside_the_grouped_one(tmp_path: Path) -> None:
    """Grouping must not hide the underlying volume. Each is a real figure and
    publishing only one invites the reader to assume the other."""
    site = build_site_data(_write(tmp_path, [_published(), _published(finding_id="f2", location={"file": "a.ts", "line": 2})]))

    assert (site.findings_total, site.decisions_total) == (2, 1)


def test_different_evidence_on_one_server_is_a_different_decision(tmp_path: Path) -> None:
    """Grouping by server and rule alone would merge a wildcard origin with a
    filesystem root, which are two separate things to fix."""
    rows = [_published(), _published(finding_id="f2", evidence="listens on 0.0.0.0")]

    assert build_site_data(_write(tmp_path, rows)).decisions_total == 2


def test_coverage_is_read_from_the_rules_rather_than_restated(tmp_path: Path) -> None:
    """Success criterion 2a. A second copy of the coverage claim is the copy
    that disagrees with the scanner."""
    site = build_site_data(_write(tmp_path, [_published()]))
    coverage = {row.rule_id: row.languages for row in site.coverage}

    assert coverage["UNICODE-CONCEAL"] == ("*",)
    assert coverage["SCOPE-OVERBROAD"] == ("typescript", "tsx")


def test_every_rule_appears_in_coverage_even_with_no_published_findings(
    tmp_path: Path,
) -> None:
    """Four of five rules publish nothing today, because they emit above
    medium and the gate withholds them. A coverage table listing only the rules
    that happened to publish would imply the others do not exist.
    """
    site = build_site_data(_write(tmp_path, [_published()]))

    assert len(site.coverage) == 5


def test_the_withheld_count_is_carried_so_the_page_cannot_omit_it(
    tmp_path: Path,
) -> None:
    """322 of 1,285 findings are published. A page showing 322 without saying
    963 are withheld overstates how clean the ecosystem is, which is the one
    direction this project must not be wrong in.
    """
    site = build_site_data(_write(tmp_path, [_published()]))

    assert site.withheld == 963


def test_coverage_figures_come_from_the_scan_not_from_the_published_rows(
    tmp_path: Path,
) -> None:
    """145 servers appear in the published findings and 1,643 were scanned.
    Deriving the denominator from the rows would report that every server
    scanned had a finding."""
    site = build_site_data(_write(tmp_path, [_published()]))

    assert (site.scanned, site.skipped, site.failed) == (1643, 357, 0)
    assert site.servers_affected == 1


def test_a_missing_summary_is_refused(tmp_path: Path) -> None:
    """Building a page without coverage would publish findings with no
    denominator, which is what criterion 1 is about."""
    data = tmp_path / "data"
    data.mkdir(parents=True)
    (data / "findings.jsonl").write_text(json.dumps(_published()) + "\n", encoding="utf-8")

    with pytest.raises(FileNotFoundError):
        build_site_data(data)


def test_rules_carry_the_text_a_reader_is_shown(tmp_path: Path) -> None:
    """Read from the rules, so a rule cannot ship without the words that
    explain it and the page cannot show different ones."""
    site = build_site_data(_write(tmp_path, [_published()]))
    scope = next(r for r in site.rules if r.rule_id == "SCOPE-OVERBROAD")

    assert scope.title
    assert scope.description
    assert scope.findings == 1
    assert scope.decisions == 1
    assert scope.servers == 1


def test_the_written_file_is_deterministic(tmp_path: Path) -> None:
    """The page data is committed, so a rebuild that reorders it would produce
    a diff on every run that means nothing."""
    data = _write(tmp_path, [_published(finding_id="f2", server_id="b/two"), _published()])
    out = tmp_path / "site-data.json"

    write_site_data(build_site_data(data), out)
    first = out.read_text()
    write_site_data(build_site_data(data), out)

    assert out.read_text() == first
    assert json.loads(first)["groups"][0]["server_id"] == "acme/one"
