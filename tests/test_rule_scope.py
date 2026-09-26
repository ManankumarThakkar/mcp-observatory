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


def test_narrowing_the_home_directory_by_any_spelling_is_not_flagged() -> None:
    """The guard must be about combining, not about one function's name.

    `path.join(homedir(), x)` was guarded; concatenation and a ternary were
    not, so two other ways of writing the correct pattern were reported as
    the mistake they avoid.
    """
    for source in (
        'const basePath = os.homedir() + "/.notes";\n',
        'const basePath = flag ? os.homedir() : "/srv/notes";\n',
        "const basePath = `${os.homedir()}/.notes`;\n",
    ):
        assert _analyze(source) == [], source


def test_a_scope_held_as_a_class_field_is_found() -> None:
    """A field is where a server that uses classes keeps its scope."""
    source = "class Server {\n  private basePath = os.homedir();\n}\n"

    assert len(_analyze(source)) == 1


def test_a_wildcard_origin_inside_a_list_is_found() -> None:
    """A list of allowed origins containing `*` allows everything."""
    assert len(_analyze('app.use(cors({ origin: ["*"] }));\n')) == 1
    assert len(_analyze('const c = { allowedOrigins: ["*"] };\n')) == 1


def test_a_wildcard_header_written_as_an_object_key_is_found() -> None:
    source = 'res.writeHead(200, { "Access-Control-Allow-Origin": "*" });\n'

    assert len(_analyze(source)) == 1


def test_the_literal_string_true_is_not_a_wildcard_origin() -> None:
    """`origin: true` reflects every origin. The string "true" is just a string.

    Conflating them reported a header whose value was the word true, and
    described it in the evidence as `*`, which was not on the line at all.
    """
    assert _analyze('res.setHeader("Access-Control-Allow-Origin", "true");\n') == []


def test_a_schema_field_named_origin_is_not_a_wildcard_origin() -> None:
    """Found in published output, not in a fixture.

    `origin: { type: String, unique: true }` is a Mongoose field definition.
    The rule walked into the object, found `true`, and reported "accepts any
    origin" - on a file with no CORS configuration in it at all. `true` means
    "reflect every origin" only when it IS the value, never when it is a
    property of some other object that happens to be the value.
    """
    source = """
const userSchema = new Schema({
  email: { type: String, required: true },
  origin: { type: String, unique: true },
  host: { type: String, default: true },
});
"""

    assert _analyze(source) == []


def test_a_bare_true_origin_is_still_a_wildcard() -> None:
    """The narrowing must not cost the real detection: `cors({ origin: true })`
    reflects whatever origin asked, which is the whole point of the rule."""
    findings = _analyze("app.use(cors({ origin: true }));")

    assert [f.evidence for f in findings] == ["accepts any origin (true)"]


def test_a_wildcard_inside_a_list_of_origins_is_still_found() -> None:
    """A list is a list of origins, so a `*` in it allows everything. That is
    different from an object, whose properties are not origins."""
    findings = _analyze('app.use(cors({ origin: ["https://a.test", "*"] }));')

    assert len(findings) == 1


# --- the local-tool precondition ----------------------------------------------

def test_a_wildcard_origin_in_a_deployed_handler_is_not_reported() -> None:
    """The rule's own claim, finally enforced.

    The description says the reach is wider than a LOCAL tool needs, and the
    implementation never checked that the server was local. Measured on the
    golden set: 36 of 60 findings came from deployed HTTP servers, and 9 of the
    10 hand-labelled ones were false positives, every contested one for this
    single reason.

    A wildcard origin cannot be combined with allow-credentials, so a browser
    never sends cookies to it. On a public read-only endpoint of a deployed
    service it is the correct configuration rather than excess reach. The claim
    holds for a local server, where a page in the user's browser could otherwise
    drive a tool on their machine, and does not hold here.
    """
    source = (
        "export default {\n"
        "  async fetch(request: Request, env: Env): Promise<Response> {\n"
        "    return new Response(JSON.stringify({ ok: true }), {\n"
        '      headers: { "access-control-allow-origin": "*" },\n'
        "    });\n"
        "  },\n"
        "};\n"
    )

    assert _analyze(source) == []


def test_a_wildcard_origin_in_a_local_server_is_still_reported() -> None:
    """The guard against over-correcting the change above.

    If this fails, narrowing the rule has silently disabled it on the code it
    exists to protect - which is the failure mode of every exclusion. A stdio
    MCP server that also opens a browser-reachable port is exactly the case the
    claim was written for.
    """
    source = (
        "const transport = new StdioServerTransport();\n"
        "await server.connect(transport);\n"
        "const app = express();\n"
        'app.use(cors({ origin: "*" }));\n'
        "app.listen(7411, '127.0.0.1');\n"
    )

    findings = _analyze(source)

    assert [f.evidence for f in findings] == ['accepts any origin ("*")']


def test_a_deployed_handler_still_has_its_other_scopes_reported() -> None:
    """Only the origin claim depends on the server being local. A deployed
    service that treats the filesystem root as its scope is overbroad whoever
    runs it, and suppressing that too would trade one silent gap for another.
    """
    source = (
        "export default {\n"
        "  async fetch(request: Request, env: Env): Promise<Response> {\n"
        '    const roots = { allowedDirectories: ["/"] };\n'
        '    return new Response(JSON.stringify(roots), { headers: { "access-control-allow-origin": "*" } });\n'
        "  },\n"
        "};\n"
    )

    evidence = [f.evidence for f in _analyze(source)]

    assert any("/" in e and "origin" not in e for e in evidence), evidence
    assert not any("origin" in e for e in evidence), evidence


def test_the_deployed_worker_fixture_is_clean() -> None:
    """A realistic remote MCP server whose wildcard origin is the correct
    configuration. It stands in for the 36 of 60 golden-set findings that came
    from deployed servers, and it must produce nothing.
    """
    assert _analyze(_fixture("clean/scope_deployed_worker.ts")) == []
