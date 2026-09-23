"""The server index: what the scan will read, written once by the crawl."""

import json
from collections.abc import Iterable
from dataclasses import asdict, fields
from pathlib import Path

from analyzer.crawler.corpus import build_corpus
from analyzer.crawler.registry import ServerRecord
from analyzer.errors import InputError

_FIELDS = tuple(field.name for field in fields(ServerRecord))


def collapse_to_index(records: Iterable[ServerRecord]) -> list[ServerRecord]:
    """One record per repository, which is what the scan should be handed.

    The orchestrator clones once per record, so an index written per registry
    entry would fetch the most-claimed repository 2,332 times and publish its
    findings as that many distinct vulnerable servers. Collapsing is the whole
    reason `build_corpus` exists, and the index has to carry it or the saving
    is reported in the coverage summary and then not taken.

    The grouping is `build_corpus`'s rather than a second copy of it, because
    two answers to "what is one repository" would eventually differ and the
    published corpus size would stop describing the scan that ran.

    A shared repository publishes under the lexicographically first name that
    claims it. The choice is arbitrary but it must be deterministic: a name
    picked by registry order would move between runs and turn one finding into
    a new finding whenever the order changed. The other names are kept in the
    corpus, so nothing is lost, but the published finding names only one of
    them and the dashboard will need to say so.
    """
    records = list(records)
    by_id = {record.server_id: record for record in records}
    return [
        by_id[repository.server_ids[0]]
        for repository in build_corpus(records).repositories
    ]


def write_server_index(path: Path, records: Iterable[ServerRecord]) -> None:
    """Write the index as one record per line.

    Spec section 6.1 names this as the crawler's output. JSON Lines rather
    than one array so a partial read is still a list of complete records, and
    so a diff shows which servers changed rather than rewriting the document.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(asdict(record), sort_keys=True) + "\n")


def load_server_index(path: Path) -> list[ServerRecord]:
    """Read the index, refusing anything it cannot read completely.

    A missing file raises rather than returning an empty list. An empty scan
    and a mistyped path look identical downstream, and the second should not
    be able to produce a run that quietly scanned nothing.

    A malformed or incomplete line raises with its line number, for the same
    reason the history does: a silently skipped server is a hole in the
    published coverage that nobody can see.

    An index that parses completely and holds no servers is refused too. That
    is the same failure as a missing file one step over: it produces the empty
    scan the paragraph above exists to prevent, and the pipeline's collapse
    guard cannot catch it on a first run, because there is no previous run to
    be smaller than.
    """
    if not path.exists():
        raise FileNotFoundError(f"no server index at {path}")

    records: list[ServerRecord] = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                records.append(ServerRecord(**{name: payload[name] for name in _FIELDS}))
            # ValueError covers both a line that is not JSON and a record the
            # ServerRecord constructor refuses, such as one naming a scheme
            # the fetcher must never be handed. The second used to escape this
            # handler and arrive with no line number, which in a file of
            # twenty-one thousand entries meant reading them to find it.
            except (ValueError, KeyError, TypeError) as exc:
                raise InputError(f"{path} is unreadable at line {number}: {exc}") from exc

    if not records:
        raise InputError(f"{path} lists no servers; a crawl that found none is a broken crawl")
    return records
