"""Every detection rule, collected explicitly.

A rule that is not in this tuple does not run. That is the point: a missing
entry is a visible gap in a list you read, whereas the import-time registry
this replaced would let a forgotten import disable a detection silently, and
report a server as clean because the check never happened.

The annotation is load-bearing rather than decorative. mypy checks every entry
against the `Rule` protocol, so a rule with a typo'd method name, a missing
`rule_id`, or the wrong return type fails the type check instead of failing at
runtime on somebody's repository.
"""

from analyzer.rules.base import Rule
from analyzer.rules.shell_exec import ShellExecUnsafeRule
from analyzer.rules.unicode_conceal import UnicodeConcealRule

ALL_RULES: tuple[Rule, ...] = (UnicodeConcealRule(), ShellExecUnsafeRule())
