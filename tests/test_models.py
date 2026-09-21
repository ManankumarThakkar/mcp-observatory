import json

from analyzer.models import Finding, Location


def _finding(
    evidence: str = "suspicious text",
    *,
    file: str = "src/index.ts",
    line: int = 42,
) -> Finding:
    return Finding(
        server_id="owner/repo",
        commit_sha="a" * 40,
        rule_id="UNICODE-CONCEAL",
        severity="critical",
        confidence="high",
        location=Location(file=file, line=line),
        evidence=evidence,
    )


def test_finding_id_is_stable_for_identical_input():
    assert _finding().finding_id == _finding().finding_id


def test_finding_id_changes_when_evidence_changes():
    assert _finding("one").finding_id != _finding("two").finding_id


def test_finding_id_resists_delimiter_injection_from_a_hostile_repository():
    """Two different findings must not share an identity.

    Both the file path and the evidence come from a repository we do not
    control, and a POSIX filename may contain ':' and '|'. If evidence were
    joined into the identity string directly, the two findings below would
    produce the identical string "owner/repo|R|x:1|y:2|e", silently merging
    into one record and hiding one of them. Hashing evidence to a fixed-length
    field first removes the ambiguity.
    """
    a = _finding("e", file="x:1|y", line=2)
    b = _finding("y:2|e", file="x", line=1)

    assert a.finding_id != b.finding_id


def test_to_dict_renders_the_documented_schema():
    """Pins the subset of spec section 8 that this plan produces.

    The four fields filled by later layers (triage, first_seen, last_seen,
    disclosure_state) are deliberately absent, so this also fails if someone
    adds a placeholder before the layer that populates it exists.
    """
    payload = _finding().to_dict()

    assert set(payload) == {
        "finding_id",
        "server_id",
        "commit_sha",
        "rule_id",
        "severity",
        "confidence",
        "location",
        "evidence",
    }
    assert payload["finding_id"] == _finding().finding_id
    assert payload["location"] == {"file": "src/index.ts", "line": 42}


def test_to_dict_is_json_serialisable():
    """A finding that cannot be written to findings.jsonl is not a finding."""
    payload = _finding().to_dict()

    assert json.loads(json.dumps(payload)) == payload
