"""Shared fixtures. Test modules must not import each other: `tests` is not
a package, so a cross-import works under pytest's path handling and fails
under mypy, which is a difference that only shows up in CI.
"""

from analyzer.report.site import CoverageRow, Decision, RuleSummary, SiteData

SITE = SiteData(
    generated_at="2026-09-25T01:10:58Z",
    published_at="2026-09-25T01:12:00Z",
    tool_version="0.1.0",
    corpus=21492,
    sampled=2000,
    sample_seed=20260923,
    scanned=1643,
    skipped=357,
    failed=0,
    findings_found=1285,
    findings_published=322,
    decisions_published=164,
    servers_affected=145,
    withheld=963,
    by_severity={"medium": 322},
    rules=(
        RuleSummary("SCOPE-OVERBROAD", "Server reach wider than its tools require", "Wide reach.",
                    ("typescript", "tsx"), 322, 164, 145),
        RuleSummary("TOOL-DESC-INJECTION", "Instructions planted in tool metadata", "Planted text.",
                    ("typescript", "tsx"), 0, 0, 0),
    ),
    coverage=(
        CoverageRow("SCOPE-OVERBROAD", "Server reach wider than its tools require", ("typescript", "tsx")),
        CoverageRow("UNICODE-CONCEAL", "Characters hidden from human review", ("*",)),
    ),
    groups=(
        Decision("acme/one", "SCOPE-OVERBROAD", "medium", "accepts any origin (*)", 16,
                 ("src/a.ts:1",), "2026-09-23T00:00:00Z", "2026-09-25T00:00:00Z"),
    ),
)
