"""SARIF output, so a maintainer sees findings in the UI they already use."""

from collections.abc import Sequence
from typing import Any

from analyzer.models import SEVERITIES, Finding
from analyzer.rules import ALL_RULES

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "mcp-observatory"
INFORMATION_URI = "https://github.com/ManankumarThakkar/mcp-observatory"

# SARIF has three levels where this project has five severities. The original
# is kept in properties.severity, so nothing is lost on the way out and the
# published index can still distinguish a critical from a high.
SEVERITY_TO_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# The one fingerprint key GitHub actually reads. Its documentation is explicit
# that code scanning "only uses the primaryLocationLineHash", so a fingerprint
# stored under any other name is silently ignored and every nightly upload
# reopens every alert that was already open.
#
# `finding_id` is what goes in it. It is deterministic and it excludes
# commit_sha for exactly this reason, so tonight's result matches last night's
# across a new commit rather than arriving as a new alert.
FINGERPRINT_KEY = "primaryLocationLineHash"

# GitHub accepts at most 25,000 results and 25,000 rules in one run, and 10 MB
# gzipped per upload. A single server's findings are nowhere near that; a
# whole-corpus document would be. Nothing here truncates, because silently
# dropping findings from a security report is worse than an upload that fails
# loudly, and the pipeline writes per-server documents.
MAX_RESULTS_PER_RUN = 25_000

_DESCRIBED_RULES = {rule.rule_id: rule for rule in ALL_RULES}


def _rule_descriptor(rule_id: str) -> dict[str, Any]:
    """The reportingDescriptor GitHub requires for each rule that fired.

    Text comes from the rule itself rather than a table here, so a rule cannot
    ship without it and the two cannot drift. A rule id with no registered
    rule still produces a valid descriptor: a document that fails to upload
    would lose every finding in it, which is a worse outcome than a thin
    description on one.
    """
    rule = _DESCRIBED_RULES.get(rule_id)
    title = rule.title if rule else rule_id
    description = rule.description if rule else f"Findings reported by {rule_id}."
    return {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": title},
        "fullDescription": {"text": description},
        "help": {"text": description},
        "defaultConfiguration": {"level": "warning"},
        "properties": {"tags": ["security", "mcp"]},
    }


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": SEVERITY_TO_LEVEL[finding.severity],
        "message": {"text": f"{finding.rule_id}: {finding.evidence}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.file},
                    # endLine repeats startLine because a Location carries one
                    # line and no columns. Inventing a span would be a claim
                    # about where the finding ends that nothing measured.
                    "region": {
                        "startLine": finding.location.line,
                        "endLine": finding.location.line,
                    },
                }
            }
        ],
        "partialFingerprints": {FINGERPRINT_KEY: finding.finding_id},
        "properties": {
            "severity": finding.severity,
            "confidence": finding.confidence,
            "serverId": finding.server_id,
            "commitSha": finding.commit_sha,
        },
    }


def to_sarif(findings: Sequence[Finding], *, tool_version: str) -> dict[str, Any]:
    """Render findings as a SARIF 2.1.0 document.

    A run with no findings is still a complete document. GitHub closes an
    alert by not seeing it in a later run, so a clean scan that emitted
    nothing would leave every previous alert open forever.

    Rules are ordered by id rather than by first appearance, so two runs over
    the same findings produce the same document and a diff means the findings
    moved.
    """
    rule_ids = sorted({finding.rule_id for finding in findings})
    index_of = {rule_id: index for index, rule_id in enumerate(rule_ids)}

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": tool_version,
                        "informationUri": INFORMATION_URI,
                        "rules": [_rule_descriptor(rule_id) for rule_id in rule_ids],
                    }
                },
                "results": [
                    _result(finding, index_of[finding.rule_id]) for finding in findings
                ],
            }
        ],
    }


# Guards the mapping against the model rather than restating it: widening
# either Literal in models.py without adding a level here fails at import.
assert set(SEVERITY_TO_LEVEL) == set(SEVERITIES), (
    "every severity needs a SARIF level; "
    f"missing {set(SEVERITIES) - set(SEVERITY_TO_LEVEL)}"
)
