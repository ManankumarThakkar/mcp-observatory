import pytest

from analyzer.parsing.trees import parse_source
from analyzer.rules.imports import ModuleBindings, bindings_for


def _bindings(source: str, modules: frozenset[str]) -> ModuleBindings:
    parsed = parse_source(source, ".ts")
    assert parsed is not None
    return bindings_for(parsed, modules)


FS = frozenset({"fs", "node:fs", "fs/promises"})
CP = frozenset({"child_process", "node:child_process"})


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import { readFile } from 'fs';", {"readFile"}),
        ("import { readFile } from 'node:fs';", {"readFile"}),
        ("import { readFile } from 'fs/promises';", {"readFile"}),
        ("import { readFile as slurp } from 'fs';", {"slurp"}),
        ("import { readFile, writeFile } from 'fs';", {"readFile", "writeFile"}),
        ("const { readFile } = require('fs');", {"readFile"}),
        ("const { readFile: slurp } = require('fs');", {"slurp"}),
    ],
)
def test_direct_bindings_are_collected(source: str, expected: set[str]) -> None:
    assert _bindings(source, FS).direct == expected


@pytest.mark.parametrize(
    "source",
    [
        "import fs from 'fs';",
        "import * as fs from 'node:fs';",
        "const fs = require('fs');",
    ],
)
def test_namespace_bindings_are_collected(source: str) -> None:
    assert _bindings(source, FS).namespaces == {"fs"}


def test_another_module_contributes_nothing() -> None:
    """The whole reason this exists.

    `readFile` is an ordinary name. A file that imports it from a wrapper
    library is not calling Node's filesystem, and reporting it would be a
    false positive of exactly the kind that cost us a clean fixture failure
    on the previous rule.
    """
    assert _bindings("import { readFile } from './my-utils';", FS) == ModuleBindings()


def test_the_same_file_can_bind_two_different_modules() -> None:
    """A server may run commands and read files, and the two must not blur."""
    source = "import { exec } from 'child_process';\nimport { readFile } from 'fs';\n"

    assert _bindings(source, FS).direct == {"readFile"}
    assert _bindings(source, CP).direct == {"exec"}


def test_nothing_bound_reports_nothing() -> None:
    assert not _bindings("const x = 1;", FS)


def test_a_binding_makes_the_result_truthy() -> None:
    """Callers check this before walking the tree, so the emptiness test matters."""
    assert _bindings("import fs from 'fs';", FS)
