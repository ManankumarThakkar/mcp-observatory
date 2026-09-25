"""SCOPE-OVERBROAD: a server reaching wider than a local tool needs to."""

from collections.abc import Iterator

from tree_sitter import Node, Query, QueryCursor

from analyzer.models import Finding, Location
from analyzer.parsing.trees import ParsedFile
from analyzer.rules.base import FileContext

# Spec section 7 defines this rule against "allowed_directories" and similar
# keys. Measured across 150 repositories, 47 of them real MCP servers, those
# keys barely exist in TypeScript: `allowedDirectories` appeared zero times,
# `allowedPaths` and `allowedHosts` once each, and every `roots` hit was a
# local variable of that name. It is a Python reference-server convention that
# did not transfer, and the rule as written would have found nothing.
#
# A quarter of servers take their allowed directories from `process.argv`,
# which is configuration supplied at launch and invisible to a static
# analyser. That portion is not detectable here at all, and saying so is more
# useful than pretending otherwise.
#
# What is detectable, and is genuinely wider than a local tool requires:
# binding every network interface (21% of servers), accepting every web origin
# (13%), and serving from the home directory or the filesystem root (28%).
# DECISIONS.md D13 records the change and why.

SCOPE_QUERY = """
(pair key: (_) @key value: (_) @value)
(variable_declarator name: (identifier) @name value: (_) @init)
(public_field_definition name: (property_identifier) @name value: (_) @init)
(call_expression function: (_) @callee arguments: (arguments) @args)
"""

# The only node types worth walking into when resolving a declared scope. An
# allowlist rather than a list of things to avoid: a list of paths or origins
# should be read entry by entry, and every other expression combines its parts
# into something narrower than any of them. An earlier version stopped only at
# calls, which guarded `path.join(homedir(), x)` while still reporting
# `homedir() + "/.notes"` and `flag ? homedir() : "/srv"` - two other
# spellings of the same correct pattern.
CONTAINER_NODES = frozenset({"array", "object", "pair"})

# Addresses that accept connections from anywhere, rather than from this
# machine only. An MCP server is normally a local tool driven over stdio; one
# that listens on every interface hands the surrounding network whatever its
# tools can do.
EVERY_INTERFACE = frozenset({"0.0.0.0", "::", "[::]"})
HOST_KEYS = frozenset({"host", "hostname", "address"})
LISTEN_METHODS = frozenset({"listen", "createServer", "bind"})

# A wildcard here lets any page in the user's browser drive the server.
CORS_KEYS = frozenset(
    {
        "origin",
        "origins",
        "allowedorigins",
        "allow_origin",
        # The header spelled as an object key, which `writeHead` takes.
        "access-control-allow-origin",
    }
)
CORS_HEADER = "access-control-allow-origin"

# `*` as a string, or `true` as a boolean, which reflects whatever origin
# asked. The string "true" is neither: an earlier version conflated them and
# reported a header whose value was the word true, describing it in the
# evidence as `*`, which was not on the line at all.
WILDCARD_ORIGIN = "*"
REFLECTS_EVERY_ORIGIN = "true"

# Names that mean "this is the extent of what the server will serve". The name
# check is what makes the value check usable: a literal "/" appears in 38% of
# servers and is almost entirely route definitions, so matching the value
# alone would report every server with a homepage.
SCOPE_NAMES = frozenset(
    {
        "basepath",
        "basedir",
        "basedirectory",
        "rootdir",
        "rootpath",
        "root",
        "serveroot",
        "workspaceroot",
        "allowedpaths",
        "alloweddirectories",
        "alloweddirs",
        "allowedroots",
        "scope",
    }
)
# Whole-filesystem or whole-home roots. A narrower path under either is fine
# and is the normal, correct pattern.
EVERY_FILE = frozenset({"/", "~", "~/", "$HOME", "C:\\", "C:/"})
HOME_CALLS = frozenset({"homedir", "userInfo"})

MAX_EVIDENCE_CHARS = 160


def _literal(parsed: ParsedFile, node: Node) -> str | None:
    """The text of a string literal, or None if this is not one.

    A doubled backslash collapses to one, so a Windows root written `"C:\\"`
    in source matches the `C:\\` this rule looks for. Without it that entry
    is unreachable while appearing to be covered.
    """
    if node.type not in ("string", "template_string"):
        return None
    raw = parsed.text(node).strip()
    inner = raw[1:-1] if len(raw) >= 2 else ""
    return inner.replace("\\\\", "\\")


# Only a list is walked when resolving an origin. A list of allowed origins
# containing `*` allows everything, just as a bare `*` does. An object is not a
# list of origins: its properties belong to whatever it configures.
#
# This was `CONTAINER_NODES`, which included objects, and it produced a finding
# on `origin: { type: String, unique: true }` - a Mongoose field definition in
# a file with no CORS configuration anywhere in it. Found by reading published
# output rather than by a fixture, which is the argument for reading published
# output.
ORIGIN_LIST_NODES = frozenset({"array"})


def _wildcard_origin(parsed: ParsedFile, node: Node) -> bool:
    """Whether this value allows every origin.

    `true` counts only as the value itself, never nested inside one. `cors({
    origin: true })` reflects whatever origin asked; `origin: { type: String,
    unique: true }` is a schema field that happens to contain the word, and
    reporting it says the server accepts any origin when nothing in the file
    configures origins at all.
    """
    if node.type == REFLECTS_EVERY_ORIGIN:
        return True

    stack = [node]
    while stack:
        current = stack.pop()
        literal = _literal(parsed, current)
        if literal is not None:
            if literal == WILDCARD_ORIGIN:
                return True
            continue
        if current.type in ORIGIN_LIST_NODES:
            stack.extend(current.named_children)
    return False


def _names_the_home_directory(parsed: ParsedFile, node: Node) -> bool:
    """Whether this expression resolves to the whole home directory.

    `os.homedir()` alone, not `path.join(os.homedir(), '.notes')`: the second
    is the correct pattern and reporting it would bury the first.
    """
    if node.type != "call_expression":
        return False
    callee = node.child_by_field_name("function")
    if callee is None:
        return False
    if callee.type == "member_expression":
        prop = callee.child_by_field_name("property")
        callee = prop if prop is not None else callee
    return parsed.text(callee) in HOME_CALLS


def _scopes_in(parsed: ParsedFile) -> Iterator[tuple[int, str]]:
    """Yield (line, what is wide) for every overbroad scope declared in code."""
    cursor = QueryCursor(Query(parsed.grammar, SCOPE_QUERY))
    found: set[tuple[int, str]] = set()

    for _, capture in cursor.matches(parsed.tree.root_node):
        keys = capture.get("key", [])
        names = capture.get("name", [])
        callees = capture.get("callee", [])

        if keys:
            key = parsed.text(keys[0]).strip("\"'").lower()
            value = capture.get("value", [None])[0]
            if value is None:
                continue

            literal = _literal(parsed, value)
            if key in HOST_KEYS and literal in EVERY_INTERFACE:
                found.add((value.start_point[0] + 1, f"listens on {literal}"))
            elif key in CORS_KEYS and _wildcard_origin(parsed, value):
                found.add(
                    (value.start_point[0] + 1, f"accepts any origin ({parsed.text(value)})")
                )
            elif key in SCOPE_NAMES:
                found.update(_wide_roots(parsed, value, key))

        elif names:
            name = parsed.text(names[0]).lower()
            init = capture.get("init", [None])[0]
            if init is not None and name in SCOPE_NAMES:
                found.update(_wide_roots(parsed, init, name))

        elif callees:
            found.update(_wide_calls(parsed, callees[0], capture.get("args", [])))

    yield from sorted(found)


def _wide_roots(parsed: ParsedFile, value: Node, label: str) -> set[tuple[int, str]]:
    """Overbroad filesystem roots inside a scope-named value.

    Walks the value so a list of paths is read entry by entry: one narrow
    entry beside `/` does not make the `/` acceptable.
    """
    found: set[tuple[int, str]] = set()
    stack = [value]
    while stack:
        current = stack.pop()
        if _names_the_home_directory(parsed, current):
            found.add((current.start_point[0] + 1, f"{label} is the whole home directory"))
            continue

        literal = _literal(parsed, current)
        if literal is not None:
            if literal in EVERY_FILE:
                found.add((current.start_point[0] + 1, f"{label} is {literal!r}"))
            continue

        # Containers only. Every other expression combines its parts into
        # something narrower: `path.join(homedir(), '.notes')`,
        # `homedir() + "/.notes"` and `flag ? homedir() : "/srv"` are all the
        # correct pattern, and walking inside any of them would find the bare
        # `homedir()` and report exactly the code that got it right.
        if current.type in CONTAINER_NODES:
            stack.extend(current.named_children)
    return found


def _wide_calls(parsed: ParsedFile, callee: Node, arguments: list[Node]) -> set[tuple[int, str]]:
    """Overbroad scope passed positionally rather than named."""
    if not arguments:
        return set()

    name = callee
    if name.type == "member_expression":
        prop = name.child_by_field_name("property")
        name = prop if prop is not None else name
    method = parsed.text(name)

    found: set[tuple[int, str]] = set()
    values = [_literal(parsed, child) for child in arguments[0].named_children]

    if method in LISTEN_METHODS:
        for node, literal in zip(arguments[0].named_children, values, strict=True):
            if literal in EVERY_INTERFACE:
                found.add((node.start_point[0] + 1, f"listens on {literal}"))

    # setHeader("Access-Control-Allow-Origin", "*") and its variants. Both
    # arguments must be literals: a value built from a variable is not
    # evidence of anything, and guessing would put noise in front of a model.
    if (
        len(values) >= 2
        and (values[0] or "").lower() == CORS_HEADER
        and values[1] == WILDCARD_ORIGIN
    ):
        node = arguments[0].named_children[1]
        found.add((node.start_point[0] + 1, "accepts any origin (*)"))

    return found


class ScopeOverbroadRule:
    """Reports a server reaching wider than a local tool requires.

    Three things are checkable without knowing what the tools do: who can
    reach the server over the network, who may call it from a browser, and how
    much of the filesystem it treats as in scope. Each is overbroad whatever
    the tools happen to be.

    Whether a *particular* scope is wider than a *particular* set of tools
    needs is a semantic judgement, which is why spec section 7 has this rule
    fully adjudicated and why every finding is low confidence. Severity stays
    medium: a wide scope enables a flaw rather than being one.
    """

    rule_id = "SCOPE-OVERBROAD"
    title = "Server reach wider than its tools require"
    # TypeScript and JavaScript, which the tsx grammar reads as one
    # family. The gate below uses this rather than a second copy of it.
    languages: tuple[str, ...] = ("typescript", "tsx")
    description = (
        "The server listens on every network interface, accepts every web "
        "origin, or treats the home directory or filesystem root as the "
        "extent of what it will serve. Each is wider than a local tool "
        "needs whatever its tools do, and widens what any other flaw can "
        "reach."
    )

    def analyze(self, ctx: FileContext) -> list[Finding]:
        parsed: ParsedFile | None = ctx.parsed
        if parsed is None or parsed.language not in self.languages:
            return []

        return [
            Finding(
                server_id=ctx.server_id,
                commit_sha=ctx.commit_sha,
                rule_id=self.rule_id,
                severity="medium",
                confidence="low",
                location=Location(file=ctx.relative_path, line=line),
                evidence=reason[:MAX_EVIDENCE_CHARS],
            )
            for line, reason in _scopes_in(parsed)
        ]
