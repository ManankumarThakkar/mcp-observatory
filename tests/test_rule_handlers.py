from tree_sitter import Node

from analyzer.parsing.trees import ParsedFile, parse_source
from analyzer.rules.handlers import REGISTRATION_NAMES, is_tool_handler
from analyzer.rules.taint import enclosing_function


def _function_around(source: str, marker: str) -> tuple[Node | None, ParsedFile]:
    parsed = parse_source(source, ".ts")
    assert parsed is not None
    assert not parsed.tree.root_node.has_error, source
    stack = [parsed.tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == "call_expression" and parsed.text(node).startswith(marker):
            return enclosing_function(node), parsed
        stack.extend(reversed(node.children))
    raise AssertionError(f"no call starting {marker!r}")


def _is_handler(source: str, marker: str = "readFileSync") -> bool:
    function, parsed = _function_around(source, marker)
    return function is not None and is_tool_handler(function, parsed)


def test_an_arrow_passed_to_registerTool_is_a_handler() -> None:
    source = "server.registerTool('r', s, async ({ file }) => { readFileSync(file); });"

    assert _is_handler(source)


def test_the_older_tool_helper_counts_too() -> None:
    source = "server.tool('r', s, async ({ file }) => { readFileSync(file); });"

    assert _is_handler(source)


def test_a_low_level_request_handler_counts() -> None:
    source = (
        "server.setRequestHandler(CallToolRequestSchema, async (req) => {"
        " readFileSync(req.params.name); });"
    )

    assert _is_handler(source)


def test_a_function_expression_handler_counts() -> None:
    source = "server.registerTool('r', s, async function ({ file }) { readFileSync(file); });"

    assert _is_handler(source)


def test_an_ordinary_helper_is_not_a_handler() -> None:
    """The distinction the whole rule now rests on.

    `readFileSync(configPath)` inside `function loadConfig(configPath)` is a
    program reading its own configuration, not an assistant reaching the
    filesystem. Measured, 97% of path findings were this.
    """
    source = "function loadConfig(configPath) { return readFileSync(configPath); }"

    assert not _is_handler(source)


def test_a_callback_nested_inside_a_handler_is_not_itself_a_handler() -> None:
    """Its parameters come from the loop, not from the assistant."""
    source = (
        "server.registerTool('r', s, async ({ files }) => {"
        " files.forEach((f) => { readFileSync(f); }); });"
    )

    assert not _is_handler(source)


def test_a_call_that_merely_takes_a_function_is_not_a_registration() -> None:
    source = "app.get('/x', async ({ file }) => { readFileSync(file); });"

    assert not _is_handler(source)


def test_every_registration_name_is_recognised() -> None:
    """Derived from the table rather than restated, so adding one extends this."""
    for name in REGISTRATION_NAMES:
        source = f"server.{name}('r', s, async ({{ file }}) => {{ readFileSync(file); }});"
        assert _is_handler(source), name
