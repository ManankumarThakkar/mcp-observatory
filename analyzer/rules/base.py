"""The contract every detection rule satisfies."""

from dataclasses import dataclass
from typing import Protocol

from analyzer.models import Finding
from analyzer.parsing.trees import ParsedFile


@dataclass(frozen=True)
class FileContext:
    """One file of a scanned repository, as a rule sees it.

    Frozen because a single context is handed to every rule for a given file.
    A rule that could mutate it would change what later rules analyse, and the
    findings would then depend on which rule happened to run first.
    """

    server_id: str
    commit_sha: str
    relative_path: str
    source: str

    # None when no grammar covers this file, which is the ordinary case for
    # Markdown and JSON. The codepoint rule needs no tree and runs on
    # everything; every rule that queries a tree must check this first.
    #
    # Present but carrying errors is a third state, and a rule should not
    # assume otherwise: 0.7% of real source files fail to parse cleanly,
    # measured over 1,430 files, rising to 2.4% for the JavaScript family.
    parsed: ParsedFile | None = None


class Rule(Protocol):
    """What a detection rule must provide.

    Structural rather than inherited: a rule is a rule by having this shape,
    so rule modules import nothing from here and can be read on their own.
    Conformance is checked where rules are collected, by annotating that
    collection as holding `Rule`, which is what makes a typo'd method name a
    type error rather than a runtime failure on somebody's repository.
    """

    rule_id: str

    # What a reader is told about this rule wherever findings are published.
    # These live on the rule rather than in a table beside it, so a rule
    # cannot ship without them and the two cannot drift apart. SARIF requires
    # a short description, a full description and help text per rule, and a
    # document missing them is rejected at upload rather than here.
    title: str
    description: str

    def analyze(self, ctx: FileContext) -> list[Finding]: ...
