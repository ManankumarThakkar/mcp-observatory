"""The contract every detection rule satisfies."""

from dataclasses import dataclass
from typing import Protocol

from analyzer.models import Finding


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


class Rule(Protocol):
    """What a detection rule must provide.

    Structural rather than inherited: a rule is a rule by having this shape,
    so rule modules import nothing from here and can be read on their own.
    Conformance is checked where rules are collected, by annotating that
    collection as holding `Rule`, which is what makes a typo'd method name a
    type error rather than a runtime failure on somebody's repository.
    """

    rule_id: str

    def analyze(self, ctx: FileContext) -> list[Finding]: ...
