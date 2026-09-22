"""Decide whether a repository actually implements a server, before publishing it."""

import re
from dataclasses import dataclass
from pathlib import Path

from analyzer.scanner import MAX_FILE_BYTES, SKIP_DIRS, safe_relative_path

# Both SDKs put the split between the two halves in the import path, in every
# released major version, which is what makes this decidable without running
# anything.
#
#   Python   v1  from mcp.server.fastmcp import FastMCP
#            v2  from mcp.server import MCPServer
#   TypeScript v1  @modelcontextprotocol/sdk/server/index.js
#              v2  @modelcontextprotocol/server
#
# The client halves are `from mcp.client` / `from mcp import Client` and
# `@modelcontextprotocol/sdk/client` / `@modelcontextprotocol/client`.
#
# Those client patterns are deliberately absent here. A repository importing
# both halves is admitted, because a server that also calls other servers is
# still a server: proxies, gateways and aggregators all do it, as does any
# server whose tests drive it through a client. Once "both" is admitted, the
# question collapses to "is there a server marker at all", and matching the
# client half would be code whose result is never read. Measured over 100 real
# candidates: 55 server only, 23 both, 4 client only, 6 neither.
SERVER_MARKERS = re.compile(
    r"@modelcontextprotocol/sdk/server"
    r"|@modelcontextprotocol/server"
    r"|from\s+mcp\.server"
    r"|import\s+mcp\.server"
    r"|\bFastMCP\s*\("
    r"|\bMCPServer\s*\("
    r"|new\s+McpServer\s*\("
)

# Wider than the scanner's set, and for a different question. The scanner reads
# what a rule might find a flaw in; this reads what might name a dependency.
# `.mjs` and `.cjs` carry imports the scanner has no reason to open, and
# `package.json` is decisive on its own under v2, where the package name says
# which half it is.
EVIDENCE_SUFFIXES = frozenset(
    {".py", ".ts", ".js", ".jsx", ".tsx", ".mjs", ".cjs", ".json"}
)


@dataclass(frozen=True)
class ServerEvidence:
    """Why we believe a repository is, or is not, a server.

    The marker and its path are kept rather than a bare boolean, because this
    decides whether a repository appears in a published index. "We looked and
    found nothing" and "we found this line in this file" are both answers
    somebody may want to check.
    """

    is_server: bool
    marker: str = ""
    path: str = ""


def looks_like_server(root: Path) -> ServerEvidence:
    """Search a cloned repository for evidence that it implements a server.

    Applied only to repositories nobody claimed. A registry entry carries its
    publisher's assertion that it is a server, and the registry holds servers
    in Rust, C#, Go and Java that these two ecosystems' markers would reject
    outright. A code-search hit carries no claim at all, which is what this
    replaces.

    Stops at the first match. The result is one citable fact rather than a
    survey, and a repository is no more a server for containing the marker
    twice.
    """
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)

        # Never followed, exactly as in the scanner. A link out of the clone
        # would let a repository borrow somebody else's code as its own
        # evidence, and the whole point here is deciding what is genuinely
        # theirs.
        if path.is_symlink():
            continue

        if not path.is_file() or path.suffix.lower() not in EVIDENCE_SUFFIXES:
            continue

        # Vendored dependencies are excluded, and this is the load-bearing
        # exclusion rather than a tidiness measure. Every client that has
        # installed its dependencies carries the server half of the SDK on
        # disk, so reading node_modules would admit the entire client
        # population as servers: the precise mistake this check exists to
        # prevent.
        if SKIP_DIRS.intersection(relative.parent.parts):
            continue

        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            source = path.read_text(encoding="utf-8-sig")
        except (UnicodeDecodeError, OSError):
            # An unreadable file is not evidence either way, and one of them
            # must not decide a repository's fate.
            continue

        match = SERVER_MARKERS.search(source)
        if match:
            return ServerEvidence(
                is_server=True,
                marker=match.group(0),
                path=safe_relative_path(relative),
            )

    return ServerEvidence(is_server=False)
