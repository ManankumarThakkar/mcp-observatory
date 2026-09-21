import dataclasses

import pytest

from analyzer.models import Finding, Location
from analyzer.rules.base import FileContext, Rule


class _StubRule:
    """A rule that conforms without inheriting anything.

    The protocol is structural, so a rule is a rule by having the right shape
    rather than by subclassing. This stub is what proves the contract
    describes something a rule author can actually satisfy, and the annotation
    in the test below is where mypy checks that claim.
    """

    rule_id = "STUB-RULE"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        return [
            Finding(
                server_id=ctx.server_id,
                commit_sha=ctx.commit_sha,
                rule_id=self.rule_id,
                severity="info",
                confidence="high",
                location=Location(file=ctx.relative_path, line=1),
                evidence=ctx.source[:20],
            )
        ]


def _ctx(source: str = "print('hello')\n") -> FileContext:
    return FileContext(
        server_id="owner/repo",
        commit_sha="a" * 40,
        relative_path="src/server.py",
        source=source,
    )


def test_a_conforming_rule_satisfies_the_protocol_and_produces_findings() -> None:
    """The annotation is the assertion mypy checks; the body checks it runs."""
    rule: Rule = _StubRule()

    findings = rule.analyze(_ctx())

    assert len(findings) == 1
    assert findings[0].rule_id == "STUB-RULE"
    assert findings[0].location.file == "src/server.py"


def test_file_context_is_immutable() -> None:
    """One context is handed to every rule for a given file.

    If a rule could mutate it, a later rule would analyse something other than
    what is on disk, and which rules ran first would change the findings.
    """
    ctx = _ctx()

    with pytest.raises(dataclasses.FrozenInstanceError):
        ctx.source = "something else"  # type: ignore[misc]
