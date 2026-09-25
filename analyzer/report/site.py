"""The page's data, computed once here rather than in the page."""

import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from analyzer.pipeline import FINDINGS_FILE, SUMMARY_FILE
from analyzer.rules import ALL_RULES


@dataclass(frozen=True)
class Decision:
    """One thing a maintainer would fix, however many lines it appears on.

    A server that sets a wildcard origin sets it on every response path.
    Measured on the first published set: 322 rows are 164 decisions, and one
    server contributed 16 rows for a single misconfiguration. Publishing rows
    as though they were problems overstates the finding count roughly twofold,
    which is the direction this project must not be wrong in.
    """

    server_id: str
    rule_id: str
    severity: str
    evidence: str
    occurrences: int
    locations: tuple[str, ...]
    first_seen: str
    last_seen: str


@dataclass(frozen=True)
class RuleSummary:
    """What a reader is told about one rule, and what it found."""

    rule_id: str
    title: str
    description: str
    languages: tuple[str, ...]
    findings: int
    decisions: int
    servers: int


@dataclass(frozen=True)
class CoverageRow:
    """Which languages a rule examines, straight from the rule."""

    rule_id: str
    title: str
    languages: tuple[str, ...]


@dataclass(frozen=True)
class SiteData:
    """Everything the dashboard renders, and nothing it has to compute.

    A page that derives its own figures is a page whose figures cannot be
    checked by running the tests. Every number here is produced by code under
    test and written to a file the page reads.
    """

    generated_at: str
    published_at: str
    tool_version: str
    scanned: int
    skipped: int
    failed: int
    findings_total: int
    decisions_total: int
    servers_affected: int
    withheld: int
    by_severity: dict[str, int]
    rules: tuple[RuleSummary, ...]
    coverage: tuple[CoverageRow, ...]
    groups: tuple[Decision, ...]


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"no published findings at {path}")
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def build_site_data(data_dir: Path) -> SiteData:
    """Read the published data and produce exactly what the page shows.

    The coverage table is read from the rules themselves rather than restated,
    because success criterion 2a states per-language coverage beside every
    aggregate figure and a second copy of that claim is the copy that would
    disagree with the scanner. Every rule appears, including the four that
    publish nothing today: they emit above medium and the gate withholds them,
    and a table listing only what happened to publish would imply the rest do
    not exist.

    The scan figures come from the summary, never from the rows. 145 servers
    appear in the published findings and 1,643 were scanned; deriving the
    denominator from the rows would report that every server scanned had a
    finding.

    The withheld count is carried so the page cannot quietly omit it. 322 of
    1,285 findings publish, and a page showing 322 without saying 963 are held
    back overstates how clean the ecosystem is.
    """
    summary_path = data_dir / SUMMARY_FILE
    if not summary_path.exists():
        raise FileNotFoundError(
            f"no summary at {summary_path}; a page without coverage publishes "
            "findings with no denominator"
        )
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    rows = _load_jsonl(data_dir / FINDINGS_FILE)

    # One decision per server, rule and evidence. Grouping by server and rule
    # alone would merge a wildcard origin with a filesystem root, which are two
    # separate things to fix.
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["server_id"], row["rule_id"], row["evidence"])].append(row)

    groups = tuple(
        Decision(
            server_id=server_id,
            rule_id=rule_id,
            severity=str(members[0]["severity"]),
            evidence=evidence,
            occurrences=len(members),
            locations=tuple(
                sorted(f"{m['location']['file']}:{m['location']['line']}" for m in members)
            ),
            first_seen=min(str(m.get("first_seen", "")) for m in members),
            last_seen=max(str(m.get("last_seen", "")) for m in members),
        )
        # Sorted so a rebuild produces no diff when nothing changed. The file is
        # committed, and a run that reordered it would churn the history for
        # no reason.
        for (server_id, rule_id, evidence), members in sorted(grouped.items())
    )

    rules = tuple(
        RuleSummary(
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            languages=tuple(rule.languages),
            findings=sum(1 for row in rows if row["rule_id"] == rule.rule_id),
            decisions=sum(1 for group in groups if group.rule_id == rule.rule_id),
            servers=len({row["server_id"] for row in rows if row["rule_id"] == rule.rule_id}),
        )
        for rule in ALL_RULES
    )

    disclosure = summary.get("disclosure", {})
    return SiteData(
        generated_at=str(summary.get("generated_at", "")),
        published_at=str(summary.get("published_at", summary.get("generated_at", ""))),
        tool_version=str(summary.get("tool_version", "")),
        scanned=int(summary.get("scanned", 0)),
        skipped=int(summary.get("skipped", 0)),
        failed=int(summary.get("failed", 0)),
        findings_total=len(rows),
        decisions_total=len(groups),
        servers_affected=len({row["server_id"] for row in rows}),
        withheld=int(disclosure.get("withheld", 0)) + int(disclosure.get("opted_out", 0)),
        by_severity=dict(sorted(Counter(str(row["severity"]) for row in rows).items())),
        rules=rules,
        coverage=tuple(
            CoverageRow(rule_id=r.rule_id, title=r.title, languages=tuple(r.languages))
            for r in ALL_RULES
        ),
        groups=groups,
    )


def write_site_data(site: SiteData, path: Path) -> None:
    """Write the page's data, deterministically.

    Sorted keys and a fixed group order, because this file is committed: a
    rebuild that reordered it would produce a diff on every run that means
    nothing about the ecosystem.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(site), indent=2, sort_keys=True) + "\n", encoding="utf-8")
