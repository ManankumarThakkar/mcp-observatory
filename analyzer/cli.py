"""Command line entry point: crawl the ecosystem, or scan one MCP server."""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from analyzer.crawler.coverage import Coverage, Sample, render_coverage, write_corpus
from analyzer.crawler.github import (
    DEFAULT_MAX_REQUESTS,
    SEARCH_QUERIES,
    GitHubSearchError,
    SearchFn,
    github_search,
    iter_discoveries,
)
from analyzer.crawler.http import FetchFailed, JsonObject, http_fetch
from analyzer.crawler.registry import RegistryError, crawl_registry
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

# Read from the environment rather than a flag: a token on a command line
# lands in shell history and in process listings.
TOKEN_VARIABLE = "GITHUB_TOKEN"

# Committed, because a reader should be able to check our coverage claim
# without first running a four-minute crawl.
DEFAULT_SUMMARY_PATH = Path("docs/coverage.md")

# Not committed. Several megabytes, and a nightly run would produce thousands
# of diff lines nobody reads. `.cache/` is already ignored.
DEFAULT_CORPUS_PATH = Path(".cache/corpus.json")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-observatory",
        description="Study MCP servers without running any of them.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    scan = subcommands.add_parser("scan", help="Scan one server's source.")
    source = scan.add_mutually_exclusive_group(required=True)
    source.add_argument("--path", help="Scan a directory already on disk.")
    source.add_argument("--repo-url", help="Clone a repository read-only, then scan it.")
    scan.add_argument(
        "--server-id", required=True, help="Identifier for the server, e.g. owner/repo."
    )

    crawl = subcommands.add_parser(
        "crawl", help="Read the registry and record what we will scan."
    )
    crawl.add_argument(
        "--summary", default=str(DEFAULT_SUMMARY_PATH), help="Where to write the summary."
    )
    crawl.add_argument(
        "--corpus", default=str(DEFAULT_CORPUS_PATH), help="Where to write the full corpus."
    )
    crawl.add_argument(
        "--with-code-search",
        action="store_true",
        help=(
            "Also search a code host for servers that were never registered. "
            f"Needs {TOKEN_VARIABLE} and takes about twenty minutes."
        ),
    )

    return parser


def run_crawl(
    *,
    fetch: Callable[[str], JsonObject],
    now: Callable[[], datetime],
    summary_path: Path,
    corpus_path: Path,
    search: SearchFn | None = None,
    search_requests: int = DEFAULT_MAX_REQUESTS,
) -> Coverage:
    """Read the whole registry, then write the summary and the corpus.

    Nothing is written until the crawl has completed. The summary is a
    published claim, and replacing it with the results of a run that died
    halfway would understate the ecosystem while looking exactly like the
    ecosystem having shrunk.

    `fetch` and `now` are injected for the same reason they are everywhere
    else here: a test of this function should not need a network or a
    particular date, and a timestamp nobody controls cannot be asserted.
    """
    crawl = crawl_registry(fetch)
    moment = now()
    coverage = Coverage.from_crawl(crawl, crawled_at=_stamp(moment))

    if search is not None:
        coverage = replace(coverage, sample=_search_sample(search, search_requests, moment))

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(render_coverage(coverage), encoding="utf-8")
    write_corpus(corpus_path, coverage)
    return coverage


def _search_sample(search: SearchFn, max_requests: int, moment: datetime) -> Sample:
    """Run one bounded code-search pass and report what it actually spent.

    The spend is counted rather than assumed. A pass can stop early when every
    query runs out of results, and reporting the budget it was allowed would
    describe a run that did not happen.

    The rotation offset comes from the date, so consecutive nightly runs begin
    at different size buckets and the sample accumulates instead of re-reading
    the same slice forever.
    """
    spent = 0

    def counted(query: str, page: int) -> JsonObject:
        nonlocal spent
        spent += 1
        return search(query, page)

    discoveries = iter_discoveries(
        counted, max_requests=max_requests, offset=moment.date().toordinal()
    )
    repo_urls = tuple(sorted({record.repo_url for record in discoveries}))
    return Sample(repo_urls=repo_urls, queries=SEARCH_QUERIES, requests_spent=spent)


def _stamp(moment: datetime) -> str:
    """Render an instant as UTC, to the second.

    Microseconds would make a committed document churn on sub-second noise,
    and a naive local time would make two machines disagree about when the
    same registry was read.
    """
    return moment.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scan(args: argparse.Namespace) -> int:
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


def _crawl(args: argparse.Namespace) -> int:
    search = None
    if args.with_code_search:
        token = os.environ.get(TOKEN_VARIABLE, "")
        if not token:
            # Refused before the registry crawl rather than after it. Code
            # search rejects anonymous requests outright, so discovering this
            # at the end would waste ninety seconds and then publish a census
            # the caller had explicitly asked to extend.
            raise FetchFailed(
                f"--with-code-search needs {TOKEN_VARIABLE}; code search rejects "
                "anonymous requests"
            )
        search = github_search(token)

    coverage = run_crawl(
        fetch=http_fetch,
        now=lambda: datetime.now(UTC),
        summary_path=Path(args.summary),
        corpus_path=Path(args.corpus),
        search=search,
    )
    corpus = coverage.corpus
    print(
        f"{coverage.entries_seen} registry entries, "
        f"{coverage.skipped_without_source} with no source, "
        f"{corpus.entries_collapsed} collapsed, "
        f"{corpus.repository_count} repositories to scan",
        file=sys.stderr,
    )
    if coverage.sample is not None:
        print(
            f"code search: {coverage.sample_size} candidates, "
            f"{coverage.sample_beyond_census} of them in no registry, "
            f"{coverage.sample.requests_spent} requests",
            file=sys.stderr,
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    try:
        return _scan(args) if args.command == "scan" else _crawl(args)
    except (
        FetchError,
        FetchFailed,
        GitHubSearchError,
        RegistryError,
        OSError,
        subprocess.SubprocessError,
    ) as exc:
        # Expected failures: a refused URL, a repository over the caps, a
        # missing directory, git exiting non-zero or timing out, an
        # unreachable registry, a registry whose shape changed. Each is
        # reported as a sentence rather than a traceback, and nothing is
        # written to stdout, so a caller parsing the output never receives a
        # partial document.
        print(f"mcp-observatory: {exc}", file=sys.stderr)
        return EXIT_SCAN_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
