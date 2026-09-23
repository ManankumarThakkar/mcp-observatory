from pathlib import Path

import pytest

from analyzer.crawler.index import (
    collapse_to_index,
    load_server_index,
    write_server_index,
)
from analyzer.crawler.registry import ServerRecord


def _record(server_id: str = "acme/thing", via: str = "registry") -> ServerRecord:
    return ServerRecord(
        server_id=server_id,
        repo_url=f"https://github.com/{server_id}",
        discovered_via=via,
    )


def test_records_round_trip_through_the_file(tmp_path: Path) -> None:
    """Spec section 6.1 names server_index.jsonl as the crawler's output.

    Until now no task wrote it, so the scan had no input it could be handed
    separately from a live crawl.
    """
    records = [_record("a/one"), _record("b/two", via="code-search")]
    path = tmp_path / "nested" / "server_index.jsonl"

    write_server_index(path, records)

    assert load_server_index(path) == records


def test_a_missing_index_is_an_error_rather_than_an_empty_run(tmp_path: Path) -> None:
    """An empty scan and a missing input file look identical downstream.

    Returning [] would let a typo in a path publish a run that scanned
    nothing, which the collapse guard would then have to catch after the fact.
    """
    with pytest.raises(FileNotFoundError):
        load_server_index(tmp_path / "absent.jsonl")


def test_a_corrupt_line_stops_the_run(tmp_path: Path) -> None:
    path = tmp_path / "server_index.jsonl"
    complete = (
        '{"server_id": "a/one", "repo_url": "https://github.com/a/one", '
        '"discovered_via": "registry"}'
    )
    path.write_text(f"{complete}\nnot json\n", encoding="utf-8")

    with pytest.raises(ValueError, match="line 2"):
        load_server_index(path)


def test_a_line_missing_a_field_names_the_line(tmp_path: Path) -> None:
    path = tmp_path / "server_index.jsonl"
    path.write_text('{"server_id": "a/one"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="line 1"):
        load_server_index(path)


def test_the_file_is_one_record_per_line(tmp_path: Path) -> None:
    path = tmp_path / "server_index.jsonl"

    write_server_index(path, [_record("a/one"), _record("b/two")])

    assert len(path.read_text(encoding="utf-8").splitlines()) == 2


def test_a_hand_edited_index_cannot_smuggle_a_local_path_past_the_fetcher(
    tmp_path: Path,
) -> None:
    """The index file is a second way into the fetcher, and it had no check.

    The https rule was enforced by the registry parser alone. Anything written
    to this file bypassed it, and the fetcher allows `file:` for its own tests,
    so an index holding `file:///` would clone a directory off the runner's
    disk and publish its paths under an attacker's server_id. The whole point
    of the rule is that the repository URL is never trusted, and a file on disk
    is no more trustworthy than the registry it came from.
    """
    path = tmp_path / "server_index.jsonl"
    path.write_text(
        '{"server_id": "attacker/controlled", "repo_url": "file:///home/runner/.ssh",'
        ' "discovered_via": "registry"}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="https"):
        load_server_index(path)


def test_one_index_entry_per_repository_however_many_names_claim_it() -> None:
    """The orchestrator clones once per record, so the index must be collapsed.

    2,332 registry names point at a single repository. An index written per
    registry entry would clone it 2,332 times and publish its findings as that
    many distinct vulnerable servers, which is the failure `build_corpus`
    exists to prevent. The grouping is reused rather than rewritten, so the
    corpus and the index cannot disagree about what a repository is.
    """
    records = [
        ServerRecord(
            server_id="c/third", repo_url="https://github.com/shared/repo", discovered_via="registry"
        ),
        ServerRecord(
            server_id="a/first", repo_url="https://github.com/shared/repo", discovered_via="registry"
        ),
        ServerRecord(
            server_id="b/solo",
            repo_url="https://github.com/solo/repo",
            discovered_via="code-search",
        ),
    ]

    index = collapse_to_index(records)

    # Lexicographically first name, so two crawls of one registry agree on
    # which name a shared repository publishes under.
    assert [(r.server_id, r.repo_url, r.discovered_via) for r in index] == [
        ("a/first", "https://github.com/shared/repo", "registry"),
        ("b/solo", "https://github.com/solo/repo", "code-search"),
    ]


def test_a_refused_url_deep_in_the_index_names_the_line_it_is_on(tmp_path: Path) -> None:
    """The scheme check refuses the record, but it refused it anonymously.

    Every other failure in this loader reports its line number, because
    finding one bad entry in twenty-one thousand otherwise means reading them.
    The https guard raises from the record's own constructor, which sits
    outside the handler that adds the line number, so it was the one failure
    that told you nothing about where it was.
    """
    path = tmp_path / "server_index.jsonl"
    path.write_text(
        '{"server_id": "a/one", "repo_url": "https://github.com/a/one", "discovered_via": "registry"}\n'
        '{"server_id": "b/two", "repo_url": "https://github.com/b/two", "discovered_via": "registry"}\n'
        '{"server_id": "c/bad", "repo_url": "file:///home/runner/.ssh", "discovered_via": "registry"}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="line 3") as caught:
        load_server_index(path)

    # Still says what was wrong, not only where.
    assert "https" in str(caught.value)


def test_an_index_with_no_records_is_refused(tmp_path: Path) -> None:
    """An empty file is the same failure as a missing one, one step over.

    A missing index already raises, because an empty scan and a mistyped path
    look identical downstream. A file that exists and holds nothing produces
    exactly that empty scan, and the collapse guard cannot catch it on a first
    run because there is no previous run to compare against.
    """
    path = tmp_path / "server_index.jsonl"
    path.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="no servers"):
        load_server_index(path)
