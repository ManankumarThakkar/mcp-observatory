import json
from typing import cast

from analyzer.models import SEVERITIES, Finding, Location, Severity
from analyzer.report.sarif import SEVERITY_TO_LEVEL, to_sarif
from analyzer.rules import ALL_RULES


def _finding(
    rule_id: str = "UNICODE-CONCEAL",
    severity: str = "critical",
    line: int = 42,
    server_id: str = "owner/repo",
) -> Finding:
    return Finding(
        server_id=server_id,
        commit_sha="a" * 40,
        rule_id=rule_id,
        # The Literal is deliberately bypassed so the table can be iterated.
        severity=cast(Severity, severity),
        confidence="high",
        location=Location(file="src/index.ts", line=line),
        evidence="unicode-tag-block U+E0041 at line 42",
    )


def test_the_document_has_the_envelope_github_requires() -> None:
    document = to_sarif([_finding()], tool_version="0.1.0")

    assert document["version"] == "2.1.0"
    assert document["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    driver = document["runs"][0]["tool"]["driver"]
    assert driver["name"] == "mcp-observatory"
    assert driver["version"] == "0.1.0"
    assert driver["informationUri"].startswith("https://")


def test_five_severities_collapse_into_three_sarif_levels() -> None:
    """SARIF has three levels. Losing the original would flatten the index."""
    for severity, level in (
        ("critical", "error"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "note"),
        ("info", "note"),
    ):
        result = to_sarif([_finding(severity=severity)], tool_version="0.1.0")["runs"][0][
            "results"
        ][0]
        assert result["level"] == level
        assert result["properties"]["severity"] == severity


def test_every_declared_severity_has_a_level() -> None:
    """Derived from the model rather than restated, so widening one widens both."""
    assert set(SEVERITY_TO_LEVEL) == set(SEVERITIES)


def test_the_fingerprint_uses_the_only_key_github_reads() -> None:
    """GitHub evaluates `primaryLocationLineHash` and ignores every other key.

    Under any other name the fingerprint is silently dropped and each nightly
    upload reopens every alert that was already open, which is the failure
    this field exists to prevent.
    """
    finding = _finding()

    result = to_sarif([finding], tool_version="0.1.0")["runs"][0]["results"][0]

    assert result["partialFingerprints"] == {"primaryLocationLineHash": finding.finding_id}


def test_the_fingerprint_survives_a_new_commit() -> None:
    """`finding_id` excludes commit_sha precisely so this holds."""
    first = _finding()
    second = Finding(
        server_id=first.server_id,
        commit_sha="b" * 40,
        rule_id=first.rule_id,
        severity=first.severity,
        confidence=first.confidence,
        location=first.location,
        evidence=first.evidence,
    )

    def fingerprint(f: Finding) -> object:
        doc = to_sarif([f], tool_version="0.1.0")
        return doc["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]

    assert fingerprint(first) == fingerprint(second)


def test_the_location_points_at_the_file_and_line() -> None:
    result = to_sarif([_finding(line=7)], tool_version="0.1.0")["runs"][0]["results"][0]
    region = result["locations"][0]["physicalLocation"]

    assert region["artifactLocation"]["uri"] == "src/index.ts"
    assert region["region"]["startLine"] == 7
    assert region["region"]["endLine"] == 7


def test_the_server_travels_with_the_result() -> None:
    """One document may carry findings for many servers.

    Without the server on each result, a reader cannot tell whose repository
    a line number refers to.
    """
    document = to_sarif(
        [_finding(server_id="a/one"), _finding(server_id="b/two")], tool_version="0.1.0"
    )

    servers = [r["properties"]["serverId"] for r in document["runs"][0]["results"]]
    assert servers == ["a/one", "b/two"]


def test_each_rule_is_described_once_however_many_findings_it_has() -> None:
    document = to_sarif(
        [_finding(), _finding(line=9), _finding(rule_id="PATH-TRAVERSAL", severity="high")],
        tool_version="0.1.0",
    )

    rules = document["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["PATH-TRAVERSAL", "UNICODE-CONCEAL"]


def test_each_rule_carries_the_text_github_requires() -> None:
    document = to_sarif([_finding()], tool_version="0.1.0")

    rule = document["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["shortDescription"]["text"]
    assert rule["fullDescription"]["text"]
    assert rule["help"]["text"]


def test_a_result_points_at_its_rule_by_index() -> None:
    document = to_sarif(
        [_finding(rule_id="PATH-TRAVERSAL", severity="high"), _finding()],
        tool_version="0.1.0",
    )
    run = document["runs"][0]
    ids = [r["id"] for r in run["tool"]["driver"]["rules"]]

    for result in run["results"]:
        assert ids[result["ruleIndex"]] == result["ruleId"]


def test_every_rule_that_ships_can_be_described() -> None:
    """Iterated from ALL_RULES so a new rule cannot ship without its text.

    A rule with no description produces a SARIF document GitHub rejects, and
    the failure would appear at upload time on a nightly run rather than here.
    """
    for rule in ALL_RULES:
        assert rule.title, rule.rule_id
        assert rule.description, rule.rule_id


def test_a_run_with_no_findings_is_still_a_valid_document() -> None:
    """A clean scan must still produce an uploadable file.

    Emitting nothing would leave yesterday's alerts open forever, because
    GitHub closes an alert by not seeing it in a later run.
    """
    document = to_sarif([], tool_version="0.1.0")

    assert document["runs"][0]["results"] == []
    assert document["runs"][0]["tool"]["driver"]["rules"] == []
    assert json.dumps(document)


def test_the_document_serialises_to_json() -> None:
    document = to_sarif([_finding()], tool_version="0.1.0")

    assert json.loads(json.dumps(document)) == document
