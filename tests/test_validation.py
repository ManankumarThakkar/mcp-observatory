from pathlib import Path

from analyzer.validation import ServerEvidence, looks_like_server


def _repo(tmp_path: Path, **files: str) -> Path:
    root = tmp_path / "repo"
    for name, content in files.items():
        path = root / name.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def test_a_python_server_import_is_evidence(tmp_path: Path) -> None:
    root = _repo(tmp_path, **{"server.py": "from mcp.server import MCPServer\n"})

    evidence = looks_like_server(root)

    assert evidence.is_server
    assert evidence.path == "server.py"
    assert "mcp.server" in evidence.marker


def test_the_older_python_high_level_class_is_evidence(tmp_path: Path) -> None:
    """v1 wrote FastMCP, v2 writes MCPServer, and both are in the wild."""
    root = _repo(tmp_path, **{"app.py": "mcp = FastMCP('Demo')\n"})

    assert looks_like_server(root).is_server


def test_the_v1_typescript_subpath_is_evidence(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        **{"index.ts": "import { Server } from '@modelcontextprotocol/sdk/server/index.js';\n"},
    )

    assert looks_like_server(root).is_server


def test_the_v2_typescript_package_is_evidence(tmp_path: Path) -> None:
    """v2 split the halves into separate packages, so the name alone says which."""
    root = _repo(
        tmp_path,
        **{"package.json": '{"dependencies": {"@modelcontextprotocol/server": "^2.0.0"}}'},
    )

    assert looks_like_server(root).is_server


def test_a_client_only_repository_is_not_a_server(tmp_path: Path) -> None:
    root = _repo(
        tmp_path,
        **{
            "main.ts": "import { Client } from '@modelcontextprotocol/sdk/client/index.js';\n",
            "run.py": "from mcp.client.stdio import stdio_client\n",
        },
    )

    evidence = looks_like_server(root)

    assert not evidence.is_server
    assert evidence.marker == ""


def test_a_repository_with_no_sdk_at_all_is_not_a_server(tmp_path: Path) -> None:
    root = _repo(tmp_path, **{"README.md": "mentions mcp servers\n", "a.py": "print(1)\n"})

    assert not looks_like_server(root).is_server


def test_a_repository_using_both_halves_counts_as_a_server(tmp_path: Path) -> None:
    """26% of candidates import both, measured over 100 real repositories.

    A server that also calls other servers is still a server: proxies,
    gateways and aggregators all do it, and so does any server whose tests
    drive it through a client. Rejecting them would discard a quarter of the
    population to avoid a false positive nobody has shown exists.
    """
    root = _repo(
        tmp_path,
        **{
            "proxy.py": (
                "from mcp.server import MCPServer\n"
                "from mcp.client.stdio import stdio_client\n"
            )
        },
    )

    assert looks_like_server(root).is_server


def test_a_vendored_dependency_is_never_evidence(tmp_path: Path) -> None:
    """Every client that installed its dependencies ships the server SDK on disk.

    Reading node_modules would admit the entire client population as servers,
    which is the exact mistake this check exists to prevent.
    """
    root = _repo(
        tmp_path,
        **{
            "main.ts": "import { Client } from '@modelcontextprotocol/sdk/client/index.js';\n",
            "node_modules__@modelcontextprotocol__sdk__server__index.js": "export class Server {}",
        },
    )

    assert not looks_like_server(root).is_server


def test_a_symlink_is_never_followed(tmp_path: Path) -> None:
    """The same trust boundary the scanner enforces, for the same reason."""
    outside = tmp_path / "host"
    outside.mkdir()
    (outside / "real.py").write_text("from mcp.server import MCPServer\n", encoding="utf-8")
    root = _repo(tmp_path, **{"placeholder.py": "print(1)\n"})
    (root / "link.py").symlink_to(outside / "real.py")

    assert not looks_like_server(root).is_server


def test_the_first_match_is_reported_rather_than_every_match(tmp_path: Path) -> None:
    """Evidence is one citable fact, not a report. The check stops when it is sure."""
    root = _repo(
        tmp_path,
        **{"a_server.py": "from mcp.server import MCPServer\n", "b_also.py": "FastMCP('x')\n"},
    )

    evidence = looks_like_server(root)

    assert evidence == ServerEvidence(
        is_server=True, marker="from mcp.server", path="a_server.py"
    )
