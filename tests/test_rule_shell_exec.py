from pathlib import Path

from analyzer.models import Finding
from analyzer.parsing.trees import parse_source
from analyzer.rules.base import FileContext
from analyzer.rules.shell_exec import ShellExecUnsafeRule

IMPORT = "import { exec, execSync, spawn, execFile } from 'child_process';\n"


def _ctx(source: str, suffix: str = ".ts") -> FileContext:
    return FileContext(
        server_id="owner/repo",
        commit_sha="a" * 40,
        relative_path=f"src/server{suffix}",
        source=source,
        parsed=parse_source(source, suffix),
    )


def _analyze(source: str, suffix: str = ".ts") -> list[Finding]:
    return ShellExecUnsafeRule().analyze(_ctx(source, suffix))


def test_a_parameter_concatenated_into_execSync_is_a_direct_finding() -> None:
    source = IMPORT + (
        "server.registerTool('read', s, async ({ path }) => {\n"
        '  return execSync("cat " + path);\n'
        "});\n"
    )

    findings = _analyze(source)

    assert len(findings) == 1
    assert findings[0].rule_id == "SHELL-EXEC-UNSAFE"
    assert findings[0].severity == "critical"
    assert findings[0].confidence == "high"
    assert findings[0].location.line == 3


def test_a_parameter_in_a_template_literal_is_a_direct_finding() -> None:
    """Template interpolation is the idiomatic way to build these strings.

    A rule that only understood concatenation would miss most real cases.
    """
    source = IMPORT + "server.tool('r', s, async ({ cmd }) => exec(`ls ${cmd}`));\n"

    findings = _analyze(source)

    assert len(findings) == 1
    assert findings[0].confidence == "high"


def test_exec_needs_no_shell_option_to_be_dangerous() -> None:
    """The Python rule keys on shell=True. In Node that would find almost nothing.

    `exec` and `execSync` run their argument through a shell every time, and
    `shell: true` appears in under 3% of repositories.
    """
    source = IMPORT + "function run(cmd) { exec(cmd); }\n"

    assert len(_analyze(source)) == 1


def test_spawn_without_a_shell_option_is_not_a_finding() -> None:
    """spawn passes its arguments as a vector, so there is no shell to inject into."""
    source = IMPORT + "function run(cmd) { spawn('git', ['log', cmd]); }\n"

    assert _analyze(source) == []


def test_spawn_with_shell_true_is_a_finding() -> None:
    source = IMPORT + "function run(cmd) { spawn('git ' + cmd, { shell: true }); }\n"

    findings = _analyze(source)

    assert len(findings) == 1
    assert findings[0].confidence == "high"


def test_execFile_with_shell_true_is_a_finding() -> None:
    source = IMPORT + "function run(cmd) { execFile('sh', ['-c', cmd], { shell: true }); }\n"

    assert len(_analyze(source)) == 1


def test_a_constant_command_is_not_a_finding() -> None:
    source = IMPORT + "function run(cmd) { execSync('git status'); }\n"

    assert _analyze(source) == []


def test_a_value_that_is_not_a_parameter_is_reported_at_low_confidence() -> None:
    """Spec section 7's partial adjudication, and the project's cost control.

    A direct path fires deterministically and never spends a model call. This
    one arrived through a helper or a reassignment, so it is flagged for the
    triage layer rather than asserted.
    """
    source = IMPORT + "function run(cmd) { execSync('cat ' + somewhereElse); }\n"

    findings = _analyze(source)

    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].confidence == "low"


def test_exec_without_the_child_process_import_is_ignored() -> None:
    """`exec` is a common method name and the corpus is full of unrelated ones.

    child_process appears in 29% of repositories and a bare `exec(` in 19%, so
    matching the name alone would report other people's ORM calls as shell
    injection.
    """
    source = "function run(cmd) { db.exec('SELECT ' + cmd); }\n"

    assert _analyze(source) == []


def test_a_require_of_child_process_also_counts() -> None:
    """Over half the JavaScript in the corpus is commonjs rather than modules."""
    source = "const { exec } = require('child_process');\nfunction r(c) { exec(c); }\n"

    assert len(_analyze(source)) == 1


def test_a_python_file_produces_nothing_in_v1() -> None:
    """D6 puts TypeScript and JavaScript first; Python is post-v1 work.

    Silently analysing Python with TypeScript queries would produce nothing
    anyway, but saying so here pins the coverage claim the dashboard makes.
    """
    source = "import subprocess\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"

    assert _analyze(source, ".py") == []


def test_a_file_with_no_tree_is_ignored() -> None:
    ctx = FileContext(
        server_id="owner/repo",
        commit_sha="a" * 40,
        relative_path="README.md",
        source="exec('rm -rf /')",
        parsed=None,
    )

    assert ShellExecUnsafeRule().analyze(ctx) == []


def test_the_evidence_names_the_sink_and_quotes_the_command() -> None:
    """Evidence is what a maintainer reads in the disclosure email."""
    source = IMPORT + "function run(cmd) { execSync('cat ' + cmd); }\n"

    evidence = _analyze(source)[0].evidence

    assert "execSync" in evidence
    assert "'cat ' + cmd" in evidence


def test_each_dangerous_call_is_reported_once() -> None:
    source = IMPORT + (
        "function run(a, b) {\n"
        "  execSync('cat ' + a);\n"
        "  exec(`ls ${b}`);\n"
        "}\n"
    )

    findings = _analyze(source)

    assert [f.location.line for f in findings] == [3, 4]


def _fixture(relative: str) -> str:
    return (Path(__file__).parent.parent / "fixtures" / relative).read_text(encoding="utf-8")


def test_the_vulnerable_fixture_is_caught_in_full() -> None:
    """Six planted flaws: four decided here, two left for the model.

    The last is a parameter passed through an escaping helper. The rule scored
    exactly that shape as a certainty on real code until the wrapped level
    existed.
    """
    findings = _analyze(_fixture("vulnerable/shell_exec_server.ts"))

    assert [f.confidence for f in findings] == [
        "high",
        "high",
        "high",
        "high",
        "low",
        "low",
    ]
    assert all(f.severity == "critical" for f in findings)


def test_the_clean_fixture_produces_nothing() -> None:
    """Realistic near-misses, which is where a precision figure is won or lost.

    An argument vector, a disabled shell, a fixed command, and a method called
    exec on a database handle. Each one looks like the vulnerable shape to a
    text search.
    """
    assert _analyze(_fixture("clean/shell_exec_safe_server.ts")) == []
