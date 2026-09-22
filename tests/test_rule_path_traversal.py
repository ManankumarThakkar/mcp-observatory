from pathlib import Path

from analyzer.models import Finding
from analyzer.parsing.trees import parse_source
from analyzer.rules.base import FileContext
from analyzer.rules.path_traversal import PathTraversalRule

IMPORT = (
    "import { readFileSync, writeFileSync, unlinkSync, readdirSync } from 'fs';\n"
    "import path from 'path';\n"
)


def _ctx(source: str, suffix: str = ".ts") -> FileContext:
    return FileContext(
        server_id="owner/repo",
        commit_sha="a" * 40,
        relative_path=f"src/server{suffix}",
        source=source,
        parsed=parse_source(source, suffix),
    )


def _analyze(source: str, suffix: str = ".ts") -> list[Finding]:
    return PathTraversalRule().analyze(_ctx(source, suffix))


def _handler(body: str, args: str = "{ file }") -> str:
    return IMPORT + f"server.registerTool('t', s, async ({args}) => {{\n  {body}\n}});\n"


def test_a_parameter_read_straight_from_disk_is_a_direct_finding() -> None:
    findings = _analyze(_handler("return readFileSync(file, 'utf8');"))

    assert len(findings) == 1
    assert findings[0].rule_id == "PATH-TRAVERSAL"
    assert findings[0].severity == "high"
    assert findings[0].confidence == "high"
    assert findings[0].location.line == 4


def test_path_join_does_not_make_it_safe() -> None:
    """The textbook Node traversal bug, and the case that matters most.

    path.join(BASE, '../../etc/passwd') resolves cleanly out of the base. A
    rule treating join as a defence would report nothing here.
    """
    findings = _analyze(_handler("return readFileSync(path.join(BASE, file));"))

    assert len(findings) == 1
    assert findings[0].confidence == "high"


def test_path_resolve_does_not_make_it_safe_either() -> None:
    assert len(_analyze(_handler("return readFileSync(path.resolve(BASE, file));"))) == 1


def test_a_helper_outside_any_handler_is_not_reported() -> None:
    """The decision this rule rests on.

    Measured over 150 real servers, treating every function's parameters as
    tool input produced 1,376 findings of which 1,330 were programs reading
    their own configuration. A path an assistant cannot influence is not a
    traversal risk, however it is written.
    """
    source = IMPORT + "function loadConfig(configPath) { return readFileSync(configPath); }\n"

    assert _analyze(source) == []


def test_a_containment_check_suppresses_the_finding() -> None:
    """How Node code actually defends itself: resolve, then prove it stayed inside.

    startsWith is the most common pattern of any measured, at 31% of the corpus.
    """
    body = (
        "const full = path.resolve(BASE, file);\n"
        "  if (!full.startsWith(BASE)) throw new Error('nope');\n"
        "  return readFileSync(full);"
    )

    assert _analyze(_handler(body)) == []


def test_path_relative_also_counts_as_a_containment_check() -> None:
    body = (
        "const full = path.resolve(BASE, file);\n"
        "  if (path.relative(BASE, full).startsWith('..')) throw new Error('nope');\n"
        "  return readFileSync(full);"
    )

    assert _analyze(_handler(body)) == []


def test_a_check_in_a_different_handler_does_not_suppress() -> None:
    """Suppression is scoped to the handler holding the sink.

    Otherwise one guarded read anywhere in a file would silence every
    unguarded one beside it.
    """
    source = (
        IMPORT
        + "server.registerTool('a', s, async ({ file }) => {\n"
        "  const full = path.resolve(BASE, file);\n"
        "  if (!full.startsWith(BASE)) throw new Error('nope');\n"
        "  return readFileSync(full);\n"
        "});\n"
        "server.registerTool('b', s, async ({ file }) => readFileSync(file));\n"
    )

    findings = _analyze(source)

    assert len(findings) == 1
    assert findings[0].location.line == 8


def test_a_constant_path_is_not_a_finding() -> None:
    assert _analyze(_handler("return readFileSync('./config.json');", args="{}")) == []


def test_writes_and_deletes_are_findings_too() -> None:
    """A traversal that writes or removes is worse than one that reads."""
    source = (
        IMPORT
        + "server.registerTool('a', s, async ({ file, body }) => writeFileSync(file, body));\n"
        "server.registerTool('b', s, async ({ file }) => unlinkSync(file));\n"
    )

    assert [f.location.line for f in _analyze(source)] == [3, 4]


def test_a_readFile_that_is_not_from_fs_is_ignored() -> None:
    """`readFile` is an ordinary method name on any storage abstraction."""
    source = (
        "import { readFile } from './my-storage';\n"
        "server.registerTool('t', s, async ({ file }) => readFile(file));\n"
    )

    assert _analyze(source) == []


def test_a_namespaced_call_is_found() -> None:
    source = (
        "import fs from 'fs';\n"
        "server.registerTool('t', s, async ({ file }) => fs.readFileSync(file));\n"
    )

    assert len(_analyze(source)) == 1


def test_a_value_that_is_not_a_parameter_is_reported_for_triage() -> None:
    findings = _analyze(_handler("return readdirSync(configuredPath);", args="{}"))

    assert len(findings) == 1
    assert findings[0].confidence == "low"


def test_a_parameter_passed_through_a_sanitiser_is_reported_for_triage() -> None:
    """A wrapper that is not a path helper may well be sanitising."""
    findings = _analyze(_handler("return readFileSync(sanitise(file));"))

    assert len(findings) == 1
    assert findings[0].confidence == "low"


def test_a_python_file_produces_nothing_in_v1() -> None:
    source = "def read(path):\n    return open(path).read()\n"

    assert _analyze(source, ".py") == []


def test_the_evidence_names_the_sink_and_the_path() -> None:
    evidence = _analyze(_handler("return readFileSync(path.join(BASE, file));"))[0].evidence

    assert "readFileSync" in evidence
    assert "path.join(BASE, file)" in evidence


def _fixture(relative: str) -> str:
    return (Path(__file__).parent.parent / "fixtures" / relative).read_text(encoding="utf-8")


def test_the_vulnerable_fixture_is_caught_in_full() -> None:
    findings = _analyze(_fixture("vulnerable/path_traversal_server.ts"))

    assert [f.confidence for f in findings] == ["high", "high", "high", "high", "low"]
    assert all(f.severity == "high" for f in findings)


def test_the_clean_fixture_produces_nothing() -> None:
    assert _analyze(_fixture("clean/path_traversal_safe_server.ts")) == []
