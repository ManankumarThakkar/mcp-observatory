"""What a file actually bound from a module, so a name match can be trusted."""

from collections.abc import Callable
from dataclasses import dataclass, field

from tree_sitter import Node

from analyzer.parsing.trees import ParsedFile


@dataclass(frozen=True)
class ModuleBindings:
    """The names a file can use to reach a given module.

    `direct` are functions imported by name, so `readFile(p)` reaches the
    module. `namespaces` are the module object itself, so only `fs.readFile(p)`
    does. Keeping them apart is what lets a caller reject `db.exec(...)` while
    accepting `cp.exec(...)`.
    """

    direct: set[str] = field(default_factory=set)
    namespaces: set[str] = field(default_factory=set)

    def __bool__(self) -> bool:
        return bool(self.direct or self.namespaces)


def bindings_for(parsed: ParsedFile, modules: frozenset[str]) -> ModuleBindings:
    """Every name this file bound from any of `modules`.

    Necessary rather than fastidious. `exec` and `readFile` are ordinary
    names, and a file may import a module for one purpose while calling a
    same-named method on something else entirely: a clean fixture calling
    `db.exec("SELECT ...")` was reported as shell injection until the previous
    rule started reading imports. A precision figure this project publishes
    cannot afford that.

    Both module syntaxes are read, because over half the JavaScript in the
    corpus is commonjs rather than ES modules.

    Shared by every rule that keys on a module's functions. It began inside
    the shell-execution rule, and moved here the moment a second rule needed
    the same analysis rather than being copied with one word changed.
    """
    direct: set[str] = set()
    namespaces: set[str] = set()

    def names_module(node: Node) -> bool:
        return parsed.text(node).strip("\"'") in modules

    stack = [parsed.tree.root_node]
    while stack:
        node = stack.pop()
        stack.extend(node.named_children)

        if node.type == "import_statement":
            source = node.child_by_field_name("source")
            if source is None or not names_module(source):
                continue
            _read_import_clauses(parsed, node, direct, namespaces)

        elif node.type == "variable_declarator":
            _read_require(parsed, node, names_module, direct, namespaces)

    return ModuleBindings(direct=direct, namespaces=namespaces)


def _read_import_clauses(
    parsed: ParsedFile, statement: Node, direct: set[str], namespaces: set[str]
) -> None:
    """Read an `import ... from '<module>'` statement.

    Walked rather than stepped through by hand: a specifier sits two levels
    below the statement, under import_clause and then named_imports, and a
    fixed-depth loop silently found none of them while still finding every
    other import form.
    """
    for clause in statement.named_children:
        if clause.type != "import_clause":
            continue
        inner = list(clause.named_children)
        while inner:
            part = inner.pop()
            if part.type == "import_specifier":
                # An alias renames the binding, so `readFile as slurp` binds
                # `slurp` and matching `readFile` would miss every call.
                chosen = part.child_by_field_name("alias") or part.child_by_field_name("name")
                if chosen is not None:
                    direct.add(parsed.text(chosen))
            elif part.type == "identifier":
                # A default import names the module object itself.
                namespaces.add(parsed.text(part))
            else:
                # named_imports and namespace_import both nest.
                inner.extend(part.named_children)


def _read_require(
    parsed: ParsedFile,
    declarator: Node,
    names_module: Callable[[Node], bool],
    direct: set[str],
    namespaces: set[str],
) -> None:
    """Read a `const ... = require('<module>')` declaration."""
    value = declarator.child_by_field_name("value")
    name = declarator.child_by_field_name("name")
    if value is None or name is None or value.type != "call_expression":
        return

    callee = value.child_by_field_name("function")
    arguments = value.child_by_field_name("arguments")
    if callee is None or arguments is None or parsed.text(callee) != "require":
        return
    if not any(names_module(argument) for argument in arguments.named_children):
        return

    if name.type == "identifier":
        namespaces.add(parsed.text(name))
    else:
        direct.update(_names_bound_by(parsed, name))


def _names_bound_by(parsed: ParsedFile, pattern: Node) -> set[str]:
    """Every name a destructuring pattern introduces, for the require form.

    Takes the value rather than the key of a renaming pair, so
    `const { readFile: slurp } = require('fs')` binds `slurp`.
    """
    names: set[str] = set()
    stack = [pattern]
    while stack:
        current = stack.pop()
        if current.type in ("identifier", "shorthand_property_identifier_pattern"):
            names.add(parsed.text(current))
            continue
        if current.type == "pair_pattern":
            value = current.child_by_field_name("value")
            if value is not None:
                stack.append(value)
            continue
        stack.extend(current.named_children)
    return names
