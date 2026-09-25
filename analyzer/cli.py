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

from analyzer import __version__
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
from analyzer.crawler.index import collapse_to_index, load_server_index, write_server_index
from analyzer.crawler.registry import RegistryError, crawl_registry
from analyzer.crawler.sample import sample_index
from analyzer.errors import InputError
from analyzer.fetcher.clone import FetchError, shallow_clone
from analyzer.orchestrator import CloneFn, ScanFn
from analyzer.pipeline import (
    CollapsedRun,
    Intake,
    PipelineResult,
    publish_from_history,
    run_pipeline,
)
from analyzer.report.merge import utc_stamp
from analyzer.report.page import render_overview
from analyzer.report.site import build_site_data, write_site_data
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

# Not committed, for the same reasons as the corpus: tens of thousands of
# lines that would churn nightly. It sits beside the corpus because it is the
# same crawl's output, and it is the one output a later command reads.
DEFAULT_INDEX_PATH = Path(".cache/server_index.jsonl")

# Fixed, so that "the 2,000-repository sample" names one specific set of
# repositories a reader can regenerate rather than whichever 2,000 a given
# night happened to draw. Published wherever a figure drawn from a sample is.
DEFAULT_SAMPLE_SEED = 20260923

# Derived from data/ and therefore not committed: a checked-in copy can go
# stale against the findings it describes, and the deploy workflow rebuilds it
# from the single source every time.
DEFAULT_SITE_DATA = Path("web/site-data.json")
DEFAULT_SITE_PAGE = Path("web/index.html")

# Published, and committed. Only findings that cleared the disclosure gate
# reach here.
DEFAULT_DATA_DIR = Path("data")

# The full history, withheld findings included. Gitignored, because this
# repository is public and a withheld finding written to a public file is a
# disclosed one.
DEFAULT_CACHE_DIR = Path(".cache")


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
    source.add_argument(
        "--index",
        help="Scan every server in a crawler index and publish the results.",
    )
    # Required for a single server, meaningless for an index, where each
    # record carries its own. argparse cannot express "required unless", so
    # the check lives in _scan where the combination is known.
    scan.add_argument("--server-id", help="Identifier for the server, e.g. owner/repo.")
    scan.add_argument(
        "--sample",
        type=int,
        help=(
            "Scan a reproducible random subset of --index, of this size. "
            "The subset depends on --seed and the server names and nothing else."
        ),
    )
    scan.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SAMPLE_SEED,
        help="Seed for --sample. Publish it beside any figure drawn from the subset.",
    )
    scan.add_argument(
        "--data-dir", default=str(DEFAULT_DATA_DIR), help="Where published results go."
    )
    scan.add_argument(
        "--cache-dir",
        default=str(DEFAULT_CACHE_DIR),
        help="Where the full history lives. Never published.",
    )

    publish = subcommands.add_parser(
        "publish",
        help="Publish what the disclosure gate allows, from the history, without scanning.",
    )
    publish.add_argument(
        "--data-dir", default=str(DEFAULT_DATA_DIR), help="Where published results go."
    )
    publish.add_argument(
        "--cache-dir", default=str(DEFAULT_CACHE_DIR), help="Where the full history lives."
    )
    publish.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would be published and withheld, and write nothing.",
    )

    site = subcommands.add_parser(
        "site", help="Build the dashboard's data from the published findings."
    )
    site.add_argument(
        "--data-dir", default=str(DEFAULT_DATA_DIR), help="Where the published results are."
    )
    site.add_argument(
        "--out", default=str(DEFAULT_SITE_DATA), help="Where to write the page's data."
    )
    site.add_argument(
        "--page", default=str(DEFAULT_SITE_PAGE), help="Where to write the overview page."
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
        "--index",
        default=str(DEFAULT_INDEX_PATH),
        help="Where to write the index the scan reads, one record per repository.",
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
    index_path: Path,
    search: SearchFn | None = None,
    search_requests: int = DEFAULT_MAX_REQUESTS,
) -> Coverage:
    """Read the whole registry, then write the summary, corpus and index.

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
    coverage = Coverage.from_crawl(crawl, crawled_at=utc_stamp(moment))

    if search is not None:
        coverage = replace(coverage, sample=_search_sample(search, search_requests, moment))

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(render_coverage(coverage), encoding="utf-8")
    write_corpus(corpus_path, coverage)
    # The scan's input, and the only one of the three a later command reads.
    # Collapsed to one record per repository, because the orchestrator clones
    # per record and the coverage summary has already reported that saving.
    write_server_index(index_path, collapse_to_index(crawl.records))
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


def _scan(args: argparse.Namespace) -> int:
    if args.index:
        return _scan_index(args)

    # A subset of one repository is that repository. Ignoring the flag would
    # scan a single server while the caller believed they had asked for a
    # sample of many, and the summary line would not say otherwise.
    if args.sample is not None:
        raise InputError("--sample applies to --index; a single repository is not a corpus")

    if not args.server_id:
        raise InputError("--server-id is required when scanning a single server")

    if args.path:
        root = Path(args.path)
        if not root.is_dir():
            raise NotADirectoryError(f"{args.path} is not a directory")
        commit_sha = LOCAL_SCAN_SHA
        report = scan_directory(root, args.server_id, commit_sha)
    else:
        # TemporaryDirectory removes the clone on the way out, on success
        # and on failure alike. The fetcher cleans up after its own
        # failures; this covers the successful path, which the fetcher
        # cannot, because the caller needs those files to scan.
        with tempfile.TemporaryDirectory() as workdir:
            result = shallow_clone(args.repo_url, Path(workdir) / "repo")
            commit_sha = result.commit_sha
            report = scan_directory(result.path, args.server_id, commit_sha)

    json.dump(
        {
            "server_id": args.server_id,
            "commit_sha": commit_sha,
            "findings": [finding.to_dict() for finding in report.findings],
            "skipped_files": [
                {"path": skip.path, "reason": skip.reason} for skip in report.skipped
            ],
        },
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 0


def run_index_scan(
    *,
    index_path: Path,
    data_dir: Path,
    cache_dir: Path,
    sample: int | None = None,
    seed: int = DEFAULT_SAMPLE_SEED,
    clone: CloneFn = shallow_clone,
    scan: ScanFn = scan_directory,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> PipelineResult:
    """Run the whole pipeline over a crawler index, or a subset of one.

    Separate from the argparse layer so a test can exercise it without
    constructing a Namespace, and so the clone and scan functions can be
    injected. A test that has to build a Namespace ends up asserting against
    argparse rather than against the pipeline.

    Disclosure records are empty, which means every high and critical finding
    is withheld. That is the correct default: the gate fails closed, and a
    record saying a maintainer was notified belongs wherever notifications are
    actually sent rather than on a flag on this command.

    The temporary working directory is owned here and removed on the way out,
    on success and on failure alike. Each server's clone lives inside it for
    as long as the scan of that server takes.
    """
    records = load_server_index(index_path)
    # Captured before sampling, because it is the denominator every published
    # figure is measured against and nothing downstream can recover it.
    intake = Intake(corpus=len(records))
    if sample is not None:
        records = sample_index(records, sample, seed=seed)
        intake = Intake(corpus=intake.corpus, sampled=sample, seed=seed)

    with tempfile.TemporaryDirectory() as workdir:
        return run_pipeline(
            records,
            intake=intake,
            clone=clone,
            scan=scan,
            workdir=Path(workdir),
            data_dir=data_dir,
            cache_dir=cache_dir,
            disclosure_records={},
            now=now(),
            tool_version=__version__,
        )


def _scan_index(args: argparse.Namespace) -> int:
    """Report what one index scan did, on stderr, as a single line."""
    result = run_index_scan(
        index_path=Path(args.index),
        data_dir=Path(args.data_dir),
        cache_dir=Path(args.cache_dir),
        sample=args.sample,
        seed=args.seed,
    )

    drawn = f" (sample of {args.sample}, seed {args.seed})" if args.sample else ""
    print(
        f"{result.scanned} scanned, {result.skipped} skipped, {result.failed} failed; "
        f"{result.published} published, {result.withheld} withheld{drawn}",
        file=sys.stderr,
    )
    return 0


def _publish_command(args: argparse.Namespace) -> int:
    """Republish from the history, or say what republishing would do.

    `--dry-run` exists because publishing findings against named third-party
    servers is not reversible in the way a local file is: once a commit is
    pushed, it is public whatever happens next. Being able to read the exact
    counts first makes that a decision rather than a discovery.
    """
    data_dir, cache_dir = Path(args.data_dir), Path(args.cache_dir)

    if args.dry_run:
        with tempfile.TemporaryDirectory() as scratch:
            # Written to a throwaway directory so the report is produced by the
            # same code path that would publish, rather than by a second
            # implementation that could disagree with it.
            result = publish_from_history(
                cache_dir=cache_dir,
                data_dir=Path(scratch),
                disclosure_records={},
                now=datetime.now(UTC),
                tool_version=__version__,
            )
        print(
            f"would publish {result.published} findings and withhold {result.withheld}; "
            "nothing written",
            file=sys.stderr,
        )
        return 0

    result = publish_from_history(
        cache_dir=cache_dir,
        data_dir=data_dir,
        disclosure_records={},
        now=datetime.now(UTC),
        tool_version=__version__,
    )
    print(
        f"{result.published} published, {result.withheld} withheld -> {data_dir}",
        file=sys.stderr,
    )
    return 0


def _site_command(args: argparse.Namespace) -> int:
    """Build the page's data from the published findings."""
    site = build_site_data(Path(args.data_dir))
    write_site_data(site, Path(args.out))

    # The page carries its data inline rather than fetching the JSON beside
    # it. A `fetch` from file:// is blocked as a cross-origin request in every
    # current browser, so a page that fetched would work on a host and be blank
    # for anyone who opened the file - including a reviewer handed the repo.
    page = Path(args.page)
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(render_overview(site), encoding="utf-8")

    print(
        f"{site.findings_published} of {site.findings_found} findings as "
        f"{site.decisions_published} decisions on "
        f"{site.servers_affected} servers, {site.withheld} withheld -> {args.page}",
        file=sys.stderr,
    )
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
        index_path=Path(args.index),
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
        if args.command == "scan":
            return _scan(args)
        if args.command == "publish":
            return _publish_command(args)
        if args.command == "site":
            return _site_command(args)
        return _crawl(args)
    except (
        CollapsedRun,
        FetchError,
        # A refused flag combination, a zero sample, a missing --server-id, an
        # index that lists no servers or names a scheme the fetcher must never
        # be handed. Each is the caller being told what to fix.
        #
        # InputError and not ValueError. Catching ValueError here also caught
        # every invariant this codebase guards - an unknown severity, a naive
        # datetime in the disclosure window, a placeholder commit sha - and
        # printed each as the same tidy line as a mistyped flag. Those guards
        # are worth having only while they are loud.
        InputError,
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
