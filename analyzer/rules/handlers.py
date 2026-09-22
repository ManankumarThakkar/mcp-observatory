"""Which functions an assistant can actually reach."""

from tree_sitter import Node

from analyzer.parsing.trees import ParsedFile
from analyzer.rules.taint import FUNCTION_NODES

# The calls that hand a function to the protocol. `registerTool` is the
# current SDK, `tool` the older helper, and `setRequestHandler` the low-level
# route; measured across 102 repositories at 20.6%, 9.8% and 17.6%.
#
# `resource` and `registerResource` are here for the same reason: a resource
# reader takes a client-supplied URI and is no less reachable than a tool.
REGISTRATION_NAMES = frozenset(
    {
        "registerTool",
        "tool",
        "setRequestHandler",
        "registerResource",
        "resource",
        "registerPrompt",
        "prompt",
    }
)


def is_tool_handler(function: Node, parsed: ParsedFile) -> bool:
    """Whether this function was handed straight to a registration call.

    This is the difference between a path an assistant can influence and one
    the program chose for itself, and for the filesystem rule it is the
    difference between 46 findings and 1,376. `readFileSync(configPath)`
    inside `loadConfig(configPath)` is a program reading its own
    configuration; the same call inside a registered handler is an assistant
    reaching the disk. Measured on 150 real servers, 97% of candidate findings
    were the former.

    Nothing nested inside a handler counts as one, whether it is a callback
    passed to another call or a function declared in the handler's body. Its
    parameters come from whoever calls it rather than from the assistant, so
    treating them as tool input would attribute the model's influence to a
    loop variable or a local helper.

    Known gap: a handler declared separately and passed by name,
    `server.tool('x', s, handleRead)`, is not recognised, because this reads
    the syntax rather than resolving the reference. Recorded rather than
    solved, because resolving it is interprocedural analysis.
    """
    current = function
    while current.parent is not None:
        parent = current.parent
        if parent.type in FUNCTION_NODES:
            # A function declared inside a handler's body is not that handler.
            # Its parameters come from whoever calls it, so climbing past this
            # boundary would hand it the assistant's reachability and
            # reintroduce the false positive this rule exists to exclude.
            return False
        if parent.type == "arguments" and parent.parent is not None:
            # The first call this function is an argument to decides it, and
            # the walk stops either way. Climbing past it would let an
            # enclosing registration claim a callback nested several levels
            # inside its handler.
            callee = parent.parent.child_by_field_name("function")
            return callee is not None and _callee_name(callee, parsed) in REGISTRATION_NAMES
        current = parent
    return False


def _callee_name(callee: Node, parsed: ParsedFile) -> str:
    if callee.type == "member_expression":
        prop = callee.child_by_field_name("property")
        if prop is not None:
            return parsed.text(prop)
    return parsed.text(callee)
