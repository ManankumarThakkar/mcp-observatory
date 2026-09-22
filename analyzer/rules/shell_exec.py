"""SHELL-EXEC-UNSAFE: tool input reaching a command interpreter."""

import re

from tree_sitter import Node, Query, QueryCursor

from analyzer.models import Confidence, Finding, Location
from analyzer.parsing.trees import ParsedFile, language_for
from analyzer.rules.base import FileContext
from analyzer.rules.taint import classify_taint, enclosing_parameters

# Node's two shells-by-default. Unlike Python, where the danger is opting in
# with shell=True, these run their first argument through /bin/sh every time.
# Keying this rule on a shell option, as the Python rule does, would find
# almost nothing: `shell: true` appears in 2.9% of repositories against
# child_process in 29.4%.
ALWAYS_SHELL = frozenset({"exec", "execSync"})

# These pass an argument vector to execve and have no shell to inject into,
# unless the caller explicitly asks for one.
SHELL_ON_REQUEST = frozenset({"spawn", "spawnSync", "execFile", "execFileSync"})

# A cheap pre-filter, so a file that never mentions the module is not parsed
# for imports at all. It is not the precision guard: that is the binding
# analysis below.
CHILD_PROCESS = re.compile(r"child_process")

MODULE_NAMES = frozenset({"child_process", "node:child_process"})

# Any call, named or via a member expression. Two things are decided below
# rather than in the query: whether the callee is genuinely from
# child_process, and whether an options argument asks for a shell. A query can
# express neither.
CALL_QUERY = """
(call_expression function: (identifier) @name) @call
(call_expression
  function: (member_expression
    object: (identifier) @object
    property: (property_identifier) @name)) @call
"""

# A parameter that is wrapped in a call, and one that arrived from somewhere
# this rule cannot see, are both judgements rather than facts, so both go to
# the triage layer at low confidence.
CONFIDENCE_BY_TAINT: dict[str, Confidence] = {
    "direct": "high",
    "wrapped": "low",
    "indirect": "low",
}

MAX_EVIDENCE_CHARS = 160


def _child_process_bindings(parsed: ParsedFile) -> tuple[set[str], set[str]]:
    """Names this file bound from child_process: direct functions, and namespaces.

    Necessary rather than fastidious. `exec` is an ordinary method name, and a
    file may import child_process for one purpose while calling `.exec` on a
    database handle for another, which the clean fixture does. Matching the
    name alone reports that as shell injection, and a precision figure this
    project publishes cannot afford it.

    Both module syntaxes are read, because over half the JavaScript in the
    corpus is commonjs rather than ES modules.
    """
    direct: set[str] = set()
    namespaces: set[str] = set()

    def module_of(node: Node) -> str:
        return parsed.text(node).strip("\"'")

    stack = [parsed.tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.named_children)

        if node.type == "import_statement":
            source = node.child_by_field_name("source")
            if source is None or module_of(source) not in MODULE_NAMES:
                continue
            # Walked rather than stepped through by hand: a specifier sits two
            # levels below the statement, under import_clause and then
            # named_imports, and a fixed-depth loop silently found none of
            # them while still finding the other import forms.
            clauses = [
                child for child in node.named_children if child.type == "import_clause"
            ]
            for clause in clauses:
                inner = list(clause.named_children)
                while inner:
                    part = inner.pop()
                    if part.type == "import_specifier":
                        # An alias renames the binding, so `exec as run` binds
                        # `run` and matching `exec` would miss every call.
                        chosen = part.child_by_field_name("alias") or part.child_by_field_name(
                            "name"
                        )
                        if chosen is not None:
                            direct.add(parsed.text(chosen))
                    elif part.type == "identifier":
                        # A default import names the module object itself.
                        namespaces.add(parsed.text(part))
                    else:
                        # named_imports and namespace_import both nest.
                        inner.extend(part.named_children)

        elif node.type == "variable_declarator":
            value = node.child_by_field_name("value")
            name = node.child_by_field_name("name")
            if value is None or name is None or value.type != "call_expression":
                continue
            callee = value.child_by_field_name("function")
            arguments = value.child_by_field_name("arguments")
            if callee is None or arguments is None or parsed.text(callee) != "require":
                continue
            if not any(module_of(a) in MODULE_NAMES for a in arguments.named_children):
                continue
            if name.type == "identifier":
                namespaces.add(parsed.text(name))
            else:
                direct.update(_names_bound_by(parsed, name))

    return direct, namespaces


def _names_bound_by(parsed: ParsedFile, pattern: Node) -> set[str]:
    """Every name a destructuring pattern introduces, for the require form."""
    names: set[str] = set()
    stack = [pattern]
    while stack:
        current = stack.pop()
        if current.type in ("identifier", "shorthand_property_identifier_pattern"):
            names.add(parsed.text(current))
            continue
        stack.extend(current.named_children)
    return names


def _options_requests_a_shell(call: Node) -> bool:
    """Whether an argument object sets `shell` to true.

    Read from the arguments rather than by matching text, so `shell: false`
    and a comment mentioning shell are both correctly ignored.
    """
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return False

    for argument in arguments.named_children:
        if argument.type != "object":
            continue
        for pair in argument.named_children:
            if pair.type != "pair":
                continue
            key = pair.child_by_field_name("key")
            value = pair.child_by_field_name("value")
            if key is None or value is None:
                continue
            if key.text and key.text.decode("utf-8", "replace").strip("'\"") == "shell":
                return value.type == "true"
    return False


def _command_arguments(call: Node) -> list[Node]:
    """Every argument whose contents can reach the shell.

    Not just the first positional. `execFile(\'sh\', [\'-c\', cmd], { shell: true })`
    puts the entire command in the argument vector, and reading only the first
    argument sees the literal \'sh\' and reports nothing: the exact shape a
    hostile server would use, and the one this rule most needs to catch.

    The options object is excluded. It carries `shell: true` rather than
    anything that gets executed, and including it would make every such call
    look tainted by the option that made it dangerous.
    """
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return []
    return [
        argument for argument in arguments.named_children if argument.type != "object"
    ]


class ShellExecUnsafeRule:
    """Reports a command interpreter reachable from a function's parameters.

    Severity is critical throughout, because the impact does not vary: a shell
    reached by attacker-influenced text is arbitrary code execution on the
    developer's machine, with their privileges and no sandbox.

    Confidence carries the uncertainty instead, and that split is the project's
    cost control. A parameter appearing in the command itself is decided here
    and never costs a model call. Anything arriving through a helper, a
    reassignment or a conditional is reported at low confidence for the triage
    layer to adjudicate. Spec section 7 calls this partial adjudication, and
    spec section 12's triage budget only holds because the obvious cases never
    reach the model.
    """

    rule_id = "SHELL-EXEC-UNSAFE"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        parsed: ParsedFile | None = ctx.parsed
        if parsed is None or parsed.language not in ("typescript", "tsx"):
            return []
        if not CHILD_PROCESS.search(ctx.source):
            return []

        grammar = language_for(parsed.language)
        if grammar is None:
            return []

        direct_bindings, namespaces = _child_process_bindings(parsed)
        if not direct_bindings and not namespaces:
            # The module is mentioned but nothing is bound from it, so no call
            # in this file can reach it.
            return []

        findings: list[Finding] = []
        # matches() rather than captures(): the callee name is only meaningful
        # alongside the call it belongs to, and captures() returns flat
        # per-name lists that have to be zipped back together, where one
        # pattern matching without one capture silently misaligns every pair
        # after it.
        for _, capture in QueryCursor(Query(grammar, CALL_QUERY)).matches(parsed.tree.root_node):
            call_nodes = capture.get("call", [])
            name_nodes = capture.get("name", [])
            if not call_nodes or not name_nodes:
                continue

            call = call_nodes[0]
            name = parsed.text(name_nodes[0])
            objects = capture.get("object", [])
            if objects:
                # `cp.exec(...)` counts only when `cp` is the module itself.
                if parsed.text(objects[0]) not in namespaces:
                    continue
            elif name not in direct_bindings:
                # A bare `exec(...)` counts only when the file imported it.
                continue

            if name in SHELL_ON_REQUEST:
                if not _options_requests_a_shell(call):
                    continue
            elif name not in ALWAYS_SHELL:
                continue

            commands = _command_arguments(call)
            if not commands:
                continue

            # The strongest path across the arguments decides. One argument
            # being a literal says nothing about the one beside it.
            parameters = enclosing_parameters(call)
            taints = [classify_taint(node, parameters) for node in commands]
            taint = next(
                (level for level in ("direct", "wrapped", "indirect") if level in taints),
                "none",
            )
            confidence = CONFIDENCE_BY_TAINT.get(taint)
            if confidence is None:
                continue

            command = next(
                (node for node, own in zip(commands, taints, strict=True) if own == taint),
                commands[0],
            )

            findings.append(
                Finding(
                    server_id=ctx.server_id,
                    commit_sha=ctx.commit_sha,
                    rule_id=self.rule_id,
                    severity="critical",
                    confidence=confidence,
                    location=Location(
                        file=ctx.relative_path,
                        line=call.start_point[0] + 1,
                    ),
                    evidence=f"{name}({parsed.text(command)[:MAX_EVIDENCE_CHARS]})",
                )
            )

        findings.sort(key=lambda finding: finding.location.line)
        return findings
