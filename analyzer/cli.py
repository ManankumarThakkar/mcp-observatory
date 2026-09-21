"""Command line entry point: scan one MCP server and report findings as JSON."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from analyzer.fetcher.clone import FetchError, shallow_clone
from analyzer.models import Finding
from analyzer.scanner import scan_directory

# A directory scanned in place was never cloned, so there is no commit to
# report. Named rather than written inline so it is greppable: findings
# carrying it describe a working copy and must never reach the published
# index, which only reports what was fetched at a known commit.
LOCAL_SCAN_SHA = "local"

# Reserved for a scan that could not be completed. A run that finishes reports
# zero whether or not it found anything, because findings are the output rather
# than a failure, and the nightly pipeline consumes that output.
EXIT_SCAN_FAILED = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-observatory",
        description="Scan an MCP server's source without running any of it.",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--path", help="Scan a directory already on disk.")
    source.add_argument("--repo-url", help="Clone a repository read-only, then scan it.")
    parser.add_argument(
        "--server-id", required=True, help="Identifier for the server, e.g. owner/repo."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        if args.path:
            root = Path(args.path)
            if not root.is_dir():
                raise NotADirectoryError(f"{args.path} is not a directory")
            commit_sha = LOCAL_SCAN_SHA
            findings: list[Finding] = scan_directory(root, args.server_id, commit_sha)
        else:
            # TemporaryDirectory removes the clone on the way out, on success
            # and on failure alike. The fetcher cleans up after its own
            # failures; this covers the successful path, which the fetcher
            # cannot, because the caller needs those files to scan.
            with tempfile.TemporaryDirectory() as workdir:
                result = shallow_clone(args.repo_url, Path(workdir) / "repo")
                commit_sha = result.commit_sha
                findings = scan_directory(result.path, args.server_id, commit_sha)
    except (FetchError, OSError, subprocess.SubprocessError) as exc:
        # Expected failures: a refused URL, a repository over the caps, a
        # missing directory, git exiting non-zero or timing out. Each is
        # reported as a sentence rather than a traceback, and nothing is
        # written to stdout, so a caller parsing the output never receives a
        # partial document.
        print(f"mcp-observatory: {exc}", file=sys.stderr)
        return EXIT_SCAN_FAILED

    json.dump(
        {
            "server_id": args.server_id,
            "commit_sha": commit_sha,
            "findings": [finding.to_dict() for finding in findings],
        },
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
