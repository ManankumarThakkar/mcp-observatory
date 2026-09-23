from pathlib import Path

from analyzer.models import Finding
from analyzer.parsing.trees import parse_source
from analyzer.rules.base import FileContext
from analyzer.rules.scope import ScopeOverbroadRule


def _ctx(source: str, suffix: str = ".ts") -> FileContext:
    return FileContext(
        server_id="owner/repo",
        commit_sha="a" * 40,
        relative_path=f"src/server{suffix}",
        source=source,
        parsed=parse_source(source, suffix),
    )


def _analyze(source: str, suffix: str = ".ts") -> list[Finding]:
    return ScopeOverbroadRule().analyze(_ctx(source, suffix))


# --- network reach ------------------------------------------------------------

def test_binding_every_interface_is_flagged() -> None:
    """0.0.0.0 reaches the whole network; 127.0.0.1 reaches only this machine.

    An MCP server is normally a local tool. Binding every interface hands the
    LAN whatever the server's tools can do.
    """
    findings = _analyze('app.listen(3000, "0.0.0.0");\n')

    assert len(findings) == 1
    assert findings[0].rule_id == "SCOPE-OVERBROAD"
    assert findings[0].severity == "medium"
    assert findings[0].confidence == "low", "every finding here awaits triage"


def test_a_host_option_bound_to_every_interface_is_flagged() -> None:
    assert len(_analyze('server.listen({ port: 3000, host: "0.0.0.0" });\n')) == 1


def test_binding_localhost_is_not_flagged() -> None:
    assert _analyze('app.listen(3000, "127.0.0.1");\n') == []
    assert _analyze('server.listen({ host: "localhost" });\n') == []


def test_a_port_number_is_not_an_address() -> None:
    """A bare listen(port) says nothing about reach and must stay silent."""
    assert _analyze("app.listen(3000);\n") == []


# --- who may call the server --------------------------------------------------

def test_a_wildcard_cors_origin_is_flagged() -> None:
    """Any website in the user's browser can then drive the server's tools."""
    assert len(_analyze('app.use(cors({ origin: "*" }));\n')) == 1


def test_reflecting_every_origin_is_flagged() -> None:
    """`origin: true` echoes the caller's origin back, which allows all of them."""
    assert len(_analyze("app.use(cors({ origin: true }));\n")) == 1


def test_a_named_origin_is_not_flagged() -> None:
    assert _analyze('app.use(cors({ origin: "https://example.com" }));\n') == []


def test_a_wildcard_cors_header_is_flagged() -> None:
    assert len(_analyze('res.setHeader("Access-Control-Allow-Origin", "*");\n')) == 1


def test_a_computed_cors_header_is_left_to_triage_only_when_wildcarded() -> None:
    """A header built from a variable is not a literal wildcard.

    The rule reports what it can see. A value it cannot resolve is not
    evidence of anything, and guessing would put noise in front of a model.
    """
    assert _analyze('res.setHeader("Access-Control-Allow-Origin", allowed);\n') == []


# --- what the server will serve -----------------------------------------------

def test_the_home_directory_as_a_base_path_is_flagged() -> None:
    assert len(_analyze("const basePath = os.homedir();\n")) == 1


def test_filesystem_root_as_a_base_path_is_flagged() -> None:
    assert len(_analyze('const rootDir = "/";\n')) == 1


def test_a_scope_key_holding_the_root_is_flagged() -> None:
    assert len(_analyze('const config = { allowedPaths: ["/"] };\n')) == 1


def test_a_root_value_under_an_unrelated_name_is_not_flagged() -> None:
    """The name check is what makes this usable.

    A literal "/" appears in 38% of servers and is almost entirely route
    definitions. Without requiring a scope-shaped name this would report
    every server that serves a homepage.
    """
    assert _analyze('const notScope = "/";\n') == []
    assert _analyze('app.get("/", handler);\n') == []
    assert _analyze('router.get("/", (req, res) => res.send("ok"));\n') == []


def test_a_narrow_base_path_is_not_flagged() -> None:
    assert _analyze('const basePath = "/srv/notes";\n') == []
    assert _analyze("const basePath = path.join(os.homedir(), '.notes');\n") == []


# --- the rule -----------------------------------------------------------------

def test_every_finding_waits_for_triage() -> None:
    """Spec section 7 has this rule fully adjudicated.

    Whether a declared scope is wider than the tools require is a semantic
    judgement. This rule only answers the narrower question of whether the
    scope is one of the few that are overbroad whatever the tools do.
    """
    source = (
        'app.listen(3000, "0.0.0.0");\n'
        'app.use(cors({ origin: "*" }));\n'
        "const rootDir = os.homedir();\n"
    )

    findings = _analyze(source)

    assert len(findings) == 3
    assert all(f.severity == "medium" and f.confidence == "low" for f in findings)
    assert [f.location.line for f in findings] == [1, 2, 3]


def test_the_evidence_says_which_scope_is_wide() -> None:
    """A maintainer reading this needs to know which of three things fired."""
    evidence = _analyze('app.listen(3000, "0.0.0.0");\n')[0].evidence

    assert "0.0.0.0" in evidence


def test_a_python_file_produces_nothing_in_v1() -> None:
    assert _analyze('CONFIG = {"allowed_directories": ["/"]}\n', ".py") == []


def test_a_file_with_no_tree_is_ignored() -> None:
    ctx = FileContext(
        server_id="owner/repo",
        commit_sha="a" * 40,
        relative_path="README.md",
        source='listen(3000, "0.0.0.0")',
        parsed=None,
    )

    assert ScopeOverbroadRule().analyze(ctx) == []


def _fixture(relative: str) -> str:
    return (Path(__file__).parent.parent / "fixtures" / relative).read_text(encoding="utf-8")


def test_the_vulnerable_fixture_is_caught_in_full() -> None:
    findings = _analyze(_fixture("vulnerable/scope_overbroad_server.ts"))

    assert len(findings) == 5
    assert all(f.severity == "medium" and f.confidence == "low" for f in findings)


def test_the_clean_fixture_produces_nothing() -> None:
    assert _analyze(_fixture("clean/scope_narrow_server.ts")) == []
