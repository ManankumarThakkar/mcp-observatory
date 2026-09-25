"""PATH-TRAVERSAL: tool input reaching the filesystem without a containment check."""

from tree_sitter import Node, Query, QueryCursor

from analyzer.models import Confidence, Finding, Location
from analyzer.parsing.trees import ParsedFile, language_for
from analyzer.rules.base import FileContext
from analyzer.rules.handlers import is_tool_handler
from analyzer.rules.imports import bindings_for
from analyzer.rules.taint import classify_taint, enclosing_function, enclosing_parameters

MODULE_NAMES = frozenset({"fs", "node:fs", "fs/promises", "node:fs/promises"})

# Filesystem calls whose first argument is a path. Reads disclose, writes and
# deletes destroy, and traversal reaches all three, so they share a rule.
#
# `stat` and `access` are deliberately absent. They reveal only whether a path
# exists, which is a weaker result than reading or altering it, and including
# them would add volume to the index without adding impact.
PATH_SINKS = frozenset(
    {
        "readFile", "readFileSync",
        "readdir", "readdirSync",
        "createReadStream", "createWriteStream",
        "writeFile", "writeFileSync",
        "appendFile", "appendFileSync",
        "mkdir", "mkdirSync",
        "copyFile", "copyFileSync",
        "rename", "renameSync",
        "unlink", "unlinkSync",
        "rm", "rmSync",
        "rmdir", "rmdirSync",
        "open", "openSync",
    }
)

# Path helpers that build a path rather than defending one. Taint passes
# straight through them, which is the whole point: `path.join(BASE, userPath)`
# resolves `../../etc/passwd` cleanly out of the base, and is the textbook Node
# traversal bug rather than a mitigation of it. Measured in the corpus at 21%
# for join and 20% for resolve, so this is the common case rather than a corner.
PATH_BUILDERS = frozenset({"join", "resolve", "normalize"})

# What defending against traversal actually looks like in Node: work out where
# the path really points, then prove it stayed inside the base. `startsWith` is
# the most common pattern of any measured here, at 31% of repositories, while
# the plan's proposed markers, realpath and path.relative, appear in 2% and 3%.
#
# Coarse on purpose. A function that checks one path and then opens a different
# one is suppressed and missed. Tracking which variable was checked is real
# dataflow analysis, which is the wrong thing to build before the golden set
# exists to say whether it is needed. Recorded in DECISIONS.md.
CONTAINMENT_CHECKS = frozenset({"startsWith", "relative", "realpath", "realpathSync"})

CALL_QUERY = """
(call_expression function: (identifier) @name) @call
(call_expression
  function: (member_expression
    object: (_) @object
    property: (property_identifier) @name)) @call
"""

CONFIDENCE_BY_TAINT: dict[str, Confidence] = {
    "direct": "high",
    "wrapped": "low",
    "indirect": "low",
}

MAX_EVIDENCE_CHARS = 160


def _root_identifier(node: Node) -> Node | None:
    """The leftmost identifier of a member expression chain.

    `fs.promises` resolves to `fs`, so a call reached through a sub-namespace
    is still attributed to the module the file imported.
    """
    current = node
    while current.type == "member_expression":
        object_node = current.child_by_field_name("object")
        if object_node is None:
            return None
        current = object_node
    return current if current.type == "identifier" else None


def _called_name(function: Node, parsed: ParsedFile) -> str:
    if function.type == "member_expression":
        prop = function.child_by_field_name("property")
        if prop is not None:
            return parsed.text(prop)
    return parsed.text(function)


def _has_containment_check(function: Node | None, parsed: ParsedFile) -> bool:
    """Whether the function holding the sink proves the path stayed put.

    Scoped to the enclosing function rather than the file. A single guarded
    read would otherwise silence every unguarded one beside it, and a file
    that reads files usually does so in several places.
    """
    if function is None:
        return False

    stack = [function]
    while stack:
        current = stack.pop()
        if current.type == "call_expression":
            callee = current.child_by_field_name("function")
            if callee is not None and _called_name(callee, parsed) in CONTAINMENT_CHECKS:
                return True
        stack.extend(current.children)
    return False


def _path_argument(call: Node) -> Node | None:
    """The first argument, which is the path in every sink listed above."""
    arguments = call.child_by_field_name("arguments")
    if arguments is None:
        return None
    for argument in arguments.named_children:
        return argument
    return None


class PathTraversalRule:
    """Reports a filesystem call reachable from a function's parameters.

    Severity is high rather than critical: reading or writing an arbitrary
    file is serious, and it is a step short of the arbitrary code execution
    that the shell rule reports.

    Confidence carries the uncertainty, as it does for every rule here. A
    parameter reaching the path directly, including through a path builder, is
    decided here and never costs a model call. Anything arriving through
    another function or from outside the handler goes to the triage layer.
    """

    rule_id = "PATH-TRAVERSAL"
    title = "Tool input reaching the filesystem unchecked"
    # TypeScript and JavaScript, which the tsx grammar reads as one
    # family. The gate below uses this rather than a second copy of it.
    languages: tuple[str, ...] = ("typescript", "tsx")
    description = (
        "A parameter of a registered tool handler reaches a file operation "
        "without anything proving the path stayed inside its intended "
        "directory. Note that path.join and path.resolve do not provide "
        "that proof: both resolve a leading ../ straight out of the base."
    )

    def analyze(self, ctx: FileContext) -> list[Finding]:
        parsed: ParsedFile | None = ctx.parsed
        if parsed is None or parsed.language not in self.languages:
            return []

        bindings = bindings_for(parsed, MODULE_NAMES)
        if not bindings:
            return []

        grammar = language_for(parsed.language)
        if grammar is None:
            return []

        findings: list[Finding] = []
        for _, capture in QueryCursor(Query(grammar, CALL_QUERY)).matches(parsed.tree.root_node):
            call_nodes = capture.get("call", [])
            name_nodes = capture.get("name", [])
            if not call_nodes or not name_nodes:
                continue

            call = call_nodes[0]
            name = parsed.text(name_nodes[0])
            if name not in PATH_SINKS:
                continue

            objects = capture.get("object", [])
            if objects:
                # The leftmost identifier, not the immediate object, so
                # `fs.promises.readFile` resolves through `fs`. Matching only a
                # bare identifier made every `fs.promises.*` call invisible
                # while `fs/promises` was declared supported.
                root = _root_identifier(objects[0])
                if root is None:
                    continue
                # Either binding kind can name an object here. A namespace is
                # the module itself, and `import { promises as fsp }` puts a
                # module object into the direct set. An unbound name, `db` or
                # `storage`, still matches neither.
                root_name = parsed.text(root)
                if root_name not in bindings.namespaces and root_name not in bindings.direct:
                    continue
            elif name not in bindings.direct:
                continue

            path_argument = _path_argument(call)
            if path_argument is None:
                continue

            function = enclosing_function(call)
            if function is None or not is_tool_handler(function, parsed):
                # Only a registered handler's parameters are reachable by an
                # assistant. Without this the rule reports every program that
                # reads its own configuration: measured on 150 real servers,
                # 1,376 findings of which 1,330 were internal helpers, against
                # 10 for the shell rule on the same servers. "Any function's
                # parameters" is a usable proxy for tool input where the sink
                # is rare, and useless where every program touches it.
                continue

            if _has_containment_check(function, parsed):
                continue

            taint = classify_taint(
                path_argument, enclosing_parameters(call), transparent=PATH_BUILDERS
            )
            confidence = CONFIDENCE_BY_TAINT.get(taint)
            if confidence is None:
                continue

            findings.append(
                Finding(
                    server_id=ctx.server_id,
                    commit_sha=ctx.commit_sha,
                    rule_id=self.rule_id,
                    severity="high",
                    confidence=confidence,
                    location=Location(
                        file=ctx.relative_path,
                        line=call.start_point[0] + 1,
                    ),
                    evidence=f"{name}({parsed.text(path_argument)[:MAX_EVIDENCE_CHARS]})",
                )
            )

        findings.sort(key=lambda finding: finding.location.line)
        return findings
