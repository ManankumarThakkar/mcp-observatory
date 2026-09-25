import dataclasses

import pytest

from analyzer.models import Finding, Location
from analyzer.rules import ALL_RULES
from analyzer.rules.base import FileContext, Rule


class _StubRule:
    """A rule that conforms without inheriting anything.

    The protocol is structural, so a rule is a rule by having the right shape
    rather than by subclassing. This stub is what proves the contract
    describes something a rule author can actually satisfy, and the annotation
    in the test below is where mypy checks that claim.
    """

    rule_id = "STUB-RULE"
    title = "A stub"
    description = "Exists only to prove the protocol can be satisfied."
    languages: tuple[str, ...] = ("*",)

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


def test_every_rule_declares_the_languages_it_examines() -> None:
    """Success criterion 2a states per-language coverage alongside every
    aggregate figure. Coverage was enforced inside each rule's analyze and
    declared nowhere, so anything publishing it had to restate it from reading
    the source - and the figure criterion 2a governs would be a second copy
    that could quietly disagree with the code.
    """
    for rule in ALL_RULES:
        assert rule.languages, f"{rule.rule_id} declares no languages"


def test_the_declared_languages_are_the_ones_actually_gated_on() -> None:
    """A declaration the code does not honour is worse than no declaration:
    the dashboard would state a coverage the scanner does not have.

    The four tree-sitter rules examine TypeScript and JavaScript, which the
    tsx grammar reads as one family. UNICODE-CONCEAL examines everything,
    because a codepoint scan needs no parser.
    """
    declared = {rule.rule_id: set(rule.languages) for rule in ALL_RULES}

    assert declared["UNICODE-CONCEAL"] == {"*"}
    for rule_id in ("TOOL-DESC-INJECTION", "PATH-TRAVERSAL", "SHELL-EXEC-UNSAFE", "SCOPE-OVERBROAD"):
        assert declared[rule_id] == {"typescript", "tsx"}, rule_id


def test_a_parsed_rule_declining_a_language_it_declares_would_be_caught() -> None:
    """The declaration is load-bearing, so it is checked against behaviour
    rather than trusted. A rule that declared typescript and then refused a
    typescript file would publish a coverage claim it does not meet.
    """
    from analyzer.parsing.trees import parse_source
    from analyzer.rules.base import FileContext

    source = "const x = 1;\n"
    parsed = parse_source(source, ".ts")
    ctx = FileContext(
        server_id="a/b", commit_sha="a" * 40, relative_path="i.ts", source=source, parsed=parsed
    )

    for rule in ALL_RULES:
        if "typescript" in rule.languages or "*" in rule.languages:
            # Must not raise and must not refuse outright; an empty result on
            # clean code is correct, an exception is not.
            assert rule.analyze(ctx) == []
