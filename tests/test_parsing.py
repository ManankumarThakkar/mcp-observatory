import threading

import pytest
from tree_sitter import Query, QueryCursor

from analyzer.parsing.trees import LANGUAGE_BY_SUFFIX, ParsedFile, language_for, parse_source


def test_a_python_file_parses_with_the_python_grammar() -> None:
    parsed = parse_source("from mcp.server import MCPServer\n", ".py")

    assert parsed is not None
    assert parsed.language == "python"
    assert not parsed.tree.root_node.has_error


def test_a_typescript_file_uses_the_typescript_grammar() -> None:
    parsed = parse_source("const x: number = 1;\n", ".ts")

    assert parsed is not None
    assert parsed.language == "typescript"
    assert not parsed.tree.root_node.has_error


def test_javascript_is_parsed_by_the_tsx_grammar() -> None:
    """Measured: the plain TypeScript grammar rejects JSX inside a .js file.

    The tsx grammar accepts commonjs, esm, modern syntax and JSX alike, which
    is what lets one package cover the whole JavaScript family and keeps the
    dependency count at three.
    """
    parsed = parse_source("const App = () => <div className='x'>hi</div>;\n", ".js")

    assert parsed is not None
    assert parsed.language == "tsx"
    assert not parsed.tree.root_node.has_error


@pytest.mark.parametrize("suffix", [".js", ".jsx", ".mjs", ".cjs", ".tsx"])
def test_every_javascript_family_suffix_reaches_a_grammar(suffix: str) -> None:
    parsed = parse_source("export const a = 1;\n", suffix)

    assert parsed is not None
    assert parsed.language == "tsx"


def test_a_file_we_do_not_parse_returns_nothing(tmp_path: object) -> None:
    """Markdown and JSON are scanned by the codepoint rule and never parsed.

    Returning None rather than raising keeps the caller a plain loop: a file
    with no grammar is an ordinary case, not an error.
    """
    assert parse_source("# title\n", ".md") is None
    assert parse_source("{}", ".json") is None


def test_the_source_bytes_are_kept_for_byte_offsets() -> None:
    """Nodes address the source by byte, and the offsets must land correctly.

    A rule slicing with a character offset would cut the wrong span in any
    file containing a non-ASCII character, which is exactly the kind of file
    the concealment rules care about.
    """
    source = "x = 'café'\ny = 'after'\n"
    parsed = parse_source(source, ".py")
    assert parsed is not None
    assert parsed.source == source.encode("utf-8")

    query = Query(parsed.grammar, "(string) @s")
    strings = QueryCursor(query).captures(parsed.tree.root_node)["s"]

    # The accented character makes the second string's byte offset differ from
    # its character offset, which is the whole point: slicing decoded text with
    # a byte offset would silently return the wrong span here.
    assert [parsed.text(node) for node in strings] == ["'café'", "'after'"]
    assert strings[1].start_byte != source.index("'after'")


def test_a_tree_can_actually_be_queried() -> None:
    """The harness is only worth anything if a rule can run a query on it.

    tree-sitter 0.25 moved query execution out of Query and into QueryCursor,
    and most examples in circulation still call query.captures(node), which
    raises. This asserts the shape the rules will use.
    """
    parsed = parse_source("def handler():\n    pass\n", ".py")
    assert parsed is not None

    query = Query(parsed.grammar, "(function_definition name: (identifier) @name)")
    captures = QueryCursor(query).captures(parsed.tree.root_node)

    assert [parsed.text(node) for node in captures["name"]] == ["handler"]


def test_a_file_that_does_not_parse_still_returns_a_tree() -> None:
    """Partial trees are useful, and refusing them would lose whole files.

    Grammars lag language features, and a repository is not required to
    compile. A rule can check `has_error` itself if it cares.
    """
    parsed = parse_source("def broken(:\n", ".py")

    assert parsed is not None
    assert parsed.tree.root_node.has_error


def test_parsing_is_safe_from_several_threads_at_once() -> None:
    """The orchestrator runs eight workers, so this is not hypothetical.

    A parser shared across threads corrupts trees rather than raising, which
    would produce wrong findings instead of an error anyone could notice.
    """
    sources = [f"def f{n}():\n    pass\n" for n in range(40)]
    results: list[ParsedFile | None] = []
    lock = threading.Lock()

    def work(source: str) -> None:
        parsed = parse_source(source, ".py")
        with lock:
            results.append(parsed)

    threads = [threading.Thread(target=work, args=(s,)) for s in sources]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 40
    assert all(p is not None and not p.tree.root_node.has_error for p in results)


def test_every_mapped_suffix_resolves_to_a_real_grammar() -> None:
    """A typo in the table would disable parsing for that language silently.

    Derived from the table rather than restated, so adding a suffix extends
    the check automatically.
    """
    for suffix, name in LANGUAGE_BY_SUFFIX.items():
        assert language_for(name) is not None, f"{suffix} maps to unknown grammar {name}"
