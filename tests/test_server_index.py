from pathlib import Path

import pytest

from analyzer.crawler.index import load_server_index, write_server_index
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
