from tree_sitter import Node

from analyzer.parsing.trees import parse_source
from analyzer.rules.taint import classify_taint, enclosing_parameters


def _find(source: str, node_type: str, suffix: str = ".ts", starts: str = "") -> Node:
    """The first node of a type whose source text starts with `starts`.

    The prefix matters. Every example here wraps the sink in another call, so
    searching for a bare call_expression returns the registration rather than
    the `exec(...)` inside it, and the test would then be asking about the
    wrong scope entirely.
    """
    parsed = parse_source(source, suffix)
    assert parsed is not None, suffix
    assert not parsed.tree.root_node.has_error, source
    stack = [parsed.tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == node_type and parsed.text(node).startswith(starts):
            return node
        stack.extend(reversed(node.children))
    raise AssertionError(f"no {node_type} starting {starts!r} in {source!r}")


def _params(source: str, suffix: str = ".ts") -> set[str]:
    kind = "call" if suffix == ".py" else "call_expression"
    sink = "subprocess.run" if suffix == ".py" else "exec("
    return enclosing_parameters(_find(source, kind, suffix, starts=sink))


def test_a_plain_parameter_is_found() -> None:
    assert _params("function run(cmd) { exec(cmd); }") == {"cmd"}


def test_a_destructured_parameter_is_found() -> None:
    """The shape every MCP tool handler uses.

    TypeScript hands the handler an object and the handler destructures it, so
    a rule that only understands plain identifiers sees no parameters at all
    here, classifies every finding as indirect, and sends the whole corpus to
    the model.
    """
    assert _params("server.tool('a', s, async ({ path }) => { exec(path); });") == {"path"}


def test_a_default_contributes_its_name_and_not_its_value() -> None:
    source = "server.tool('a', s, async ({ path, mode = 'sh' }) => { exec(path); });"

    assert _params(source) == {"path", "mode"}


def test_rest_and_array_patterns_are_found() -> None:
    assert _params("function run([first, second], ...others) { exec(first); }") == {
        "first",
        "second",
        "others",
    }


def test_a_nested_destructure_is_found() -> None:
    source = "server.tool('a', s, async ({ opts: { cmd } }) => { exec(cmd); });"

    assert _params(source) == {"cmd"}


def test_a_single_unparenthesised_arrow_parameter_is_found() -> None:
    """`async path => exec(path)` puts the name in a different field entirely."""
    assert _params("const f = path => { exec(path); };") == {"path"}


def test_a_type_annotation_is_not_a_parameter_name() -> None:
    """Annotations are identifiers too, and naming one would poison the match."""
    assert _params("function run(cmd: CommandName) { exec(cmd); }") == {"cmd"}


def test_a_method_parameter_is_found() -> None:
    source = "class S { run(cmd) { exec(cmd); } }"

    assert _params(source) == {"cmd"}


def test_the_innermost_function_wins() -> None:
    """A callback inside a handler is its own scope.

    Taking the outer function's parameters would attribute tool input to a
    value that never came from it.
    """
    source = "function outer(a) { [1].forEach((b) => { exec(b); }); }"

    assert _params(source) == {"b"}


def test_a_call_outside_any_function_has_no_parameters() -> None:
    assert _params("exec('ls');") == set()


def test_python_parameters_are_found_too() -> None:
    """Python rules are the first post-v1 work and will reuse this."""
    source = "def run(cmd, mode='sh', *rest):\n    subprocess.run(cmd, shell=True)\n"

    assert _params(source, ".py") == {"cmd", "mode", "rest"}


def test_taint_is_direct_when_a_parameter_appears() -> None:
    node = _find("function run(cmd) { exec('ls ' + cmd); }", "binary_expression")

    assert classify_taint(node, {"cmd"}) == "direct"


def test_taint_is_indirect_when_some_other_identifier_appears() -> None:
    node = _find("function run(cmd) { exec('ls ' + other); }", "binary_expression")

    assert classify_taint(node, {"cmd"}) == "indirect"


def test_taint_is_none_for_a_pure_literal() -> None:
    node = _find("function run(cmd) { exec('ls -la'); }", "string")

    assert classify_taint(node, {"cmd"}) == "none"


def test_a_parameter_passed_through_a_call_is_wrapped_not_direct() -> None:
    """A visible sanitiser should not be asserted as a vulnerability.

    Found on real code: `execSync(`sage -c "${escapeShellString(code)}"`)`
    scored high confidence while the parameter was plainly being escaped. The
    wrapper may or may not be correct, which is what the triage layer is for.
    """
    node = _find(
        "function run(code) { exec(`sage -c ${escapeShellString(code)}`); }",
        "template_string",
    )

    assert classify_taint(node, {"code"}) == "wrapped"


def test_a_bare_parameter_beside_a_wrapped_one_is_still_direct() -> None:
    """One escaped value says nothing about the one next to it."""
    node = _find(
        "function run(a, b) { exec(`x ${escape(a)} ${b}`); }",
        "template_string",
    )

    assert classify_taint(node, {"a", "b"}) == "direct"


def test_a_call_on_the_parameter_itself_is_still_wrapped() -> None:
    """`path.trim()` is a method call on the value, and may well sanitise it."""
    node = _find("function run(path) { exec('cat ' + path.trim()); }", "binary_expression")

    assert classify_taint(node, {"path"}) == "wrapped"


def test_a_transparent_call_does_not_hide_a_parameter() -> None:
    """path.join is the bug, not the fix.

    `readFileSync(path.join(BASE, userPath))` is the textbook Node traversal
    flaw: join happily resolves `../../etc/passwd` straight out of the base.
    Treating it as a wrapper, the way an escaping helper is treated, would
    score the single most important case as uncertain and hand it to the
    model.
    """
    node = _find(
        "function read(p) { readFileSync(path.join(BASE, p)); }",
        "call_expression",
        starts="path.join",
    )

    assert classify_taint(node, {"p"}, transparent=frozenset({"join"})) == "direct"


def test_a_transparent_call_still_hides_nothing_it_did_not_wrap() -> None:
    """Only the named functions are transparent; everything else still wraps."""
    node = _find(
        "function read(p) { readFileSync(path.join(BASE, escape(p))); }",
        "call_expression",
        starts="path.join",
    )

    assert classify_taint(node, {"p"}, transparent=frozenset({"join"})) == "wrapped"


def test_transparency_is_opt_in() -> None:
    """The shell rule must keep its behaviour, where every call is a wrapper."""
    node = _find(
        "function read(p) { readFileSync(path.join(BASE, p)); }",
        "call_expression",
        starts="path.join",
    )

    assert classify_taint(node, {"p"}) == "wrapped"
