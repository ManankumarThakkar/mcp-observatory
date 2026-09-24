"""Draw the hand-labelled sample: per rule, reproducibly, without losing work."""

from collections.abc import Collection, Mapping, Sequence
from pathlib import Path
from typing import Any

from analyzer.models import Finding
from analyzer.parsing.trees import LANGUAGE_BY_SUFFIX
from analyzer.sampling import draw
from evals.golden.context import CONTEXT_LINES

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
