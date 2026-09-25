"""Draw the hand-labelled sample: per rule, reproducibly, without losing work."""

import argparse
import json
import sys
import tempfile
from collections import Counter
from collections.abc import Collection, Mapping, Sequence
from pathlib import Path
from typing import Any

from analyzer.cli import DEFAULT_SAMPLE_SEED
from analyzer.crawler.index import load_server_index
from analyzer.fetcher.clone import shallow_clone
from analyzer.models import Finding
from analyzer.orchestrator import CloneFn, ScanFn
from analyzer.parsing.trees import LANGUAGE_BY_SUFFIX
from analyzer.sampling import draw
from analyzer.scanner import scan_directory
from evals.golden.context import CONTEXT_LINES, capture_for_findings

# Spec section 10 targets 200 to 300 findings overall. Sixty per rule across
# five rules lands inside that, and sixty is roughly where a proportion's
# confidence interval stops being wider than the differences the benchmark is
# trying to detect between adjudicators.
PER_RULE_TARGET = 60

# A file no grammar covers still carries findings: UNICODE-CONCEAL needs no
# parser and fires on Markdown, JSON and anything else. Calling that "other"
# rather than excluding it keeps the sample representative of what the scanner
# actually reports.
UNKNOWN_LANGUAGE = "other"


def live_findings(records: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Only the findings the most recent scan actually produced.

    The history is cumulative by design: `merge_findings` keeps a finding
    absent from one run, because a server that could not be checked is not a
    server that got fixed. That is right for a trend and wrong for a golden
    set, which has to measure the scanner as it is now.

    Measured after a TOOL-DESC-INJECTION fix on 2026-09-25: 175 of 602 findings
    in the history were no longer produced. Drawing sixty from that picks about
    seventeen the capture then refuses, so the sample comes up short of its
    per-rule target - silently, and concentrated in whichever rule was most
    recently corrected, which is exactly the rule whose precision the fix was
    meant to change.

    `last_seen` rather than a date argument, because the caller should not have
    to know when the last scan ran to ask for its output.
    """
    if not records:
        return []
    latest = max(str(record["last_seen"]) for record in records)
    return [record for record in records if str(record["last_seen"]) == latest]


def stratified_sample(
    findings: Sequence[Finding],
    *,
    per_rule: int,
    seed: int,
    keep: Collection[str] = (),
) -> list[Finding]:
    """Up to `per_rule` findings from each rule, drawn at random within a rule.

    Random inside a stratum, guaranteed across strata. A uniform draw over the
    whole population satisfies "sampled, not curated" and then fails its
    purpose: measured on the real corpus, SCOPE-OVERBROAD and
    TOOL-DESC-INJECTION are 71% of all findings, so a uniform sample of 300
    would take about seven UNICODE-CONCEAL findings and report a precision for
    that rule that means nothing.

    The cost is real and must be stated wherever the numbers appear: the
    unweighted precision over this sample is NOT the corpus precision, because
    quiet rules are over-represented on purpose. The scoring script reports
    per-rule figures and a population-weighted total, and METHOD.md says so
    wherever they are quoted.

    Drawing per rule also means a rule added later cannot disturb the rules
    already drawn, since each stratum is drawn from its own findings alone.

    `keep` holds the finding ids already drawn, and they are kept before
    anything new is taken. The hash order is stable per item, but the cut is
    not: a later scan producing a finding that happens to hash above one
    already drawn would push it out of the top sixty and detach a label
    somebody spent minutes making. Relying on the order alone looked like it
    gave this guarantee and did not, which is why the guarantee is written
    down here rather than inferred from the draw.
    """
    by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)

    keeping = set(keep)
    drawn: list[Finding] = []
    for rule_id in sorted(by_rule):
        candidates = by_rule[rule_id]
        held = [f for f in candidates if f.finding_id in keeping]
        fresh = [f for f in candidates if f.finding_id not in keeping]
        # Top up to the target rather than drawing the target afresh, so the
        # set grows toward per_rule instead of being replaced each time.
        shortfall = max(0, per_rule - len(held))
        drawn.extend(held)
        drawn.extend(draw(fresh, shortfall, seed=seed, key=lambda f: (f.finding_id,)))
    return drawn


def _language(path: str) -> str:
    suffix = Path(path).suffix.lower()
    return LANGUAGE_BY_SUFFIX.get(suffix, UNKNOWN_LANGUAGE)


def build_entries(
    findings: Sequence[Finding],
    *,
    contexts: Mapping[str, str],
    existing: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Turn drawn findings into labellable entries, preserving work already done.

    Entry ids are append-only and carried across re-draws. Labelling three
    hundred findings is hours of somebody's time, and a re-draw after a later
    scan that renumbered the set would silently detach every label from the
    finding it was made about. So an entry already drawn keeps both its id and
    its label, and only genuinely new findings take new numbers.

    The id is a sequence number rather than anything derived from the finding.
    A derived id would hash the same public inputs `finding_id` does and would
    therefore be the same lookup key back to the server that
    `evals.golden.redact` refuses to publish.

    A finding with no captured window is left out. The capture drops a finding
    whose code no longer produces it, and an entry nobody can read is an entry
    nobody can label; a blank context would instead be judged as though the
    surrounding code were empty.

    `flagged_offset` is where the flagged line sits inside the window, which is
    the window size except near the top of a file, where the capture clamped
    and the centre moved. Publishing a constant would point at the wrong line
    for every finding in the first dozen lines of a file.
    """
    kept = {entry["finding_id"]: entry for entry in existing}
    highest = max(
        (int(str(entry["entry_id"]).removeprefix("g-")) for entry in existing), default=0
    )

    entries: list[dict[str, Any]] = []
    for finding in findings:
        context = contexts.get(finding.finding_id)
        if context is None:
            continue

        previous = kept.get(finding.finding_id)
        if previous is None:
            highest += 1
            entry_id, label = f"g-{highest:04d}", None
        else:
            entry_id, label = str(previous["entry_id"]), previous.get("label")

        entries.append(
            {
                "entry_id": entry_id,
                "finding_id": finding.finding_id,
                "server_id": finding.server_id,
                "commit_sha": finding.commit_sha,
                "file": finding.location.file,
                "line": finding.location.line,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "language": _language(finding.location.file),
                "context": context,
                "flagged_offset": min(finding.location.line - 1, CONTEXT_LINES),
                "label": label,
            }
        )
    return entries


def draw_golden_set(
    *,
    history_path: Path,
    index_path: Path,
    entries_path: Path,
    per_rule: int = PER_RULE_TARGET,
    seed: int,
    clone: CloneFn,
    scan: ScanFn,
    workdir: Path,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Draw the sample, capture each window, and write the labellable entries.

    Reads any existing entries first and passes their finding ids through the
    draw, so re-running after a later scan tops the set up rather than
    replacing it. Labelling is hours of a person's time and a re-draw that
    discarded it would be the most expensive kind of silent failure here.
    """
    records = [
        json.loads(line)
        for line in history_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    findings = [Finding.from_dict(record) for record in live_findings(records)]
    existing: list[dict[str, Any]] = []
    if entries_path.exists():
        existing = [
            json.loads(line)
            for line in entries_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    drawn = stratified_sample(
        findings,
        per_rule=per_rule,
        seed=seed,
        keep={str(entry["finding_id"]) for entry in existing},
    )
    repo_urls = {r.server_id: r.repo_url for r in load_server_index(index_path)}
    captured = capture_for_findings(
        drawn, repo_urls=repo_urls, clone=clone, scan=scan, workdir=workdir
    )
    entries = build_entries(drawn, contexts=captured.contexts, existing=existing)

    entries_path.parent.mkdir(parents=True, exist_ok=True)
    entries_path.write_text(
        "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in entries),
        encoding="utf-8",
    )
    return entries, captured.dropped


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--history", type=Path, default=Path(".cache/history.jsonl"))
    parser.add_argument("--index", type=Path, default=Path(".cache/server_index.jsonl"))
    parser.add_argument("--entries", type=Path, default=Path(".cache/golden-entries.jsonl"))
    parser.add_argument("--per-rule", type=int, default=PER_RULE_TARGET)
    parser.add_argument("--seed", type=int, default=DEFAULT_SAMPLE_SEED)
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as workdir:
        entries, dropped = draw_golden_set(
            history_path=args.history,
            index_path=args.index,
            entries_path=args.entries,
            per_rule=args.per_rule,
            seed=args.seed,
            clone=shallow_clone,
            scan=scan_directory,
            workdir=Path(workdir),
        )

    counts = Counter(entry["rule_id"] for entry in entries)
    print(f"{len(entries)} entries written to {args.entries}", file=sys.stderr)
    for rule, n in sorted(counts.items()):
        print(f"  {rule:24} {n}", file=sys.stderr)
    if dropped:
        print(f"{len(dropped)} findings dropped, uncapturable:", file=sys.stderr)
        for reason, n in Counter(v[:60] for v in dropped.values()).most_common():
            print(f"  {n:4}  {reason}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
