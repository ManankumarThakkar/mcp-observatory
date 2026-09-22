"""How tool input reaches an expression, shared by the rules that care."""

from typing import Literal

from tree_sitter import Node

Taint = Literal["direct", "wrapped", "indirect", "none"]

# Every node type that introduces a new parameter scope, in both languages.
# Python is here because Python rules are the first post-v1 work and this
# module is the one place that would otherwise be copied to support them.
FUNCTION_NODES = frozenset(
    {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
        "function_definition",
    }
)

# A name, wherever it appears inside a parameter pattern. `{ path }`
# destructures to a shorthand property identifier rather than a plain
# identifier, which is the form every MCP tool handler uses.
NAME_NODES = frozenset({"identifier", "shorthand_property_identifier_pattern"})

# Fields inside a parameter that are not names. `value` holds a default, so
# `{ mode = 'sh' }` must contribute `mode` and not `'sh'`. `type` holds an
# annotation, and `cmd: CommandName` must not contribute `CommandName`, which
# would put a type name into the set a taint match is tested against.
NOT_A_NAME_FIELD = ("value", "type", "right")

# Literal nodes in either language. An expression made only of these has no
# identifier in it at all and cannot carry tool input.
LITERAL_NODES = frozenset(
    {"string", "template_string", "concatenated_string", "number", "true", "false"}
)


def enclosing_function(node: Node) -> Node | None:
    """The nearest function containing this node.

    Nearest rather than outermost: a callback inside a handler is its own
    scope, and taking the outer function's parameters would attribute tool
    input to a value that never came from it.
    """
    current: Node | None = node
    while current is not None and current.type not in FUNCTION_NODES:
        current = current.parent
    return current


def _names_in(pattern: Node) -> set[str]:
    """Every name bound by a parameter pattern.

    Walks the pattern rather than reading one field, because TypeScript
    parameters are patterns and not names: a handler written
    `async ({ path, mode = 'sh' }) => ...` binds two names inside an
    object_pattern, and array, rest and nested patterns all nest further. A
    reader that only understood plain identifiers would find nothing at all in
    the shape every MCP tool handler uses.
    """
    names: set[str] = set()
    stack = [pattern]
    while stack:
        current = stack.pop()
        if current.type in NAME_NODES:
            names.add(current.text.decode("utf-8", "replace") if current.text else "")
            continue

        if current.type == "pair_pattern":
            # `{ opts: { cmd } }` binds `cmd` and not `opts`. The key names a
            # property on the incoming object; the value is the pattern that
            # actually introduces names. This is the one place where the value
            # is the part to keep, which is why it cannot share the rule below.
            value = current.child_by_field_name("value")
            if value is not None:
                stack.append(value)
            continue

        skip = {
            child.id
            for field in NOT_A_NAME_FIELD
            if (child := current.child_by_field_name(field)) is not None
        }
        stack.extend(child for child in current.named_children if child.id not in skip)
    return names - {""}


def enclosing_parameters(node: Node) -> set[str]:
    """Names of the parameters of the function lexically enclosing `node`.

    These stand in for tool input. A tool handler's parameters are exactly the
    values an assistant can influence, and any other function's parameters are
    the closest thing to that signal without recognising every registration
    style in the ecosystem.
    """
    function = enclosing_function(node)
    if function is None:
        return set()

    # `parameters` covers every declared function and a parenthesised arrow.
    # A single unparenthesised arrow parameter, `path => ...`, is held in
    # `parameter` instead, and reading only the plural field misses it.
    container = function.child_by_field_name("parameters") or function.child_by_field_name(
        "parameter"
    )
    if container is None:
        return set()

    return _names_in(container)


def classify_taint(
    node: Node, parameters: set[str], *, transparent: frozenset[str] = frozenset()
) -> Taint:
    """Classify how tool input reaches this expression.

    "direct"   a parameter appears bare in the expression. Deterministic
               enough to report without a model looking at it, which is what
               keeps the triage budget intact.
    "wrapped"  every occurrence of a parameter passes through a call first, so
               something may be sanitising it. Found on real code:
               `exec(`sage -c "${escapeShellString(code)}"`)` was being
               asserted as a vulnerability while the value was plainly being
               escaped. Whether the wrapper is correct is a judgement, so it
               goes to the triage layer rather than being decided here. This
               is structural on purpose: a list of known-good sanitiser names
               would go stale and would never cover a bespoke helper.
    "indirect" something non-constant appears but no parameter does, so the
               value arrived through a helper, a reassignment or a
               conditional. Reported at low confidence for adjudication.
    "none"     a literal with no identifiers. Not attacker-influenced, and not
               a finding.

    `transparent` names functions that pass taint through rather than hiding
    it. A caller needs this when the wrapping call is the vulnerability rather
    than a defence against it: `path.join(BASE, userPath)` resolves
    `../../etc/passwd` straight out of the base, so treating it as a sanitiser
    would score the textbook Node traversal bug as merely uncertain. It is
    opt-in, because for the shell rule every wrapper genuinely might be
    escaping something.
    """
    identifiers = _identifiers(node)
    if not identifiers:
        return "none"
    if not identifiers & parameters:
        return "indirect"
    return "direct" if _bare_parameters(node, parameters, transparent) else "wrapped"


def _bare_parameters(node: Node, parameters: set[str], transparent: frozenset[str]) -> bool:
    """Whether any parameter reaches the expression without passing through a call.

    One escaped value says nothing about the one beside it, so a single bare
    occurrence is enough to keep the whole expression direct. A call named in
    `transparent` is not counted as passing through at all.
    """
    stack: list[tuple[Node, bool]] = [(node, False)]
    while stack:
        current, inside_call = stack.pop()
        if (
            current.type == "identifier"
            and not inside_call
            and current.text
            and current.text.decode("utf-8", "replace") in parameters
        ):
            return True

        # Everything under a call is wrapped, except a plain identifier being
        # called. `escape(a)` hides `a`; `path.trim()` hides `path`, because a
        # method call on the value transforms it just as a function call does;
        # but a parameter used directly as the callee does not hide itself.
        function = current.child_by_field_name("function")
        is_call = current.type in ("call_expression", "call")
        if is_call and function is not None and _called_name(function) in transparent:
            # Named as passing taint through, so its arguments are no more
            # hidden than if they had been written inline.
            is_call = False
        exempt = function.id if function is not None and function.type == "identifier" else None
        for child in current.children:
            nested = inside_call or (is_call and child.id != exempt)
            stack.append((child, nested))
    return False


def _called_name(function: Node) -> str:
    """The bare name being called, whether written plainly or on an object.

    `join(a, b)` and `path.join(a, b)` are the same function, and a rule
    naming transparent helpers should not have to list both spellings.
    """
    if function.type == "member_expression":
        prop = function.child_by_field_name("property")
        function = prop if prop is not None else function
    return function.text.decode("utf-8", "replace") if function.text else ""


def _identifiers(node: Node) -> set[str]:
    found: set[str] = set()
    stack = [node]
    while stack:
        current = stack.pop()
        if current.type == "identifier" and current.text:
            found.add(current.text.decode("utf-8", "replace"))
        elif current.type in LITERAL_NODES:
            # A template string may interpolate, so its children still matter.
            stack.extend(current.named_children)
            continue
        stack.extend(current.children)
    return found
