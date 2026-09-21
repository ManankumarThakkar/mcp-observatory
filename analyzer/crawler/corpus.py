"""Collapse registry entries into the repositories a scan actually reads."""

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from analyzer.crawler.registry import ServerRecord


@dataclass(frozen=True)
class Repository:
    """One repository, and every registry name that claims it.

    The names are kept rather than reduced to a count. A repository published
    under many names is itself a reportable fact, and the index has to be able
    to say so. Keeping only a number would turn that into a silent deletion,
    and keeping only one name would pick a winner arbitrarily.
    """

    repo_url: str
    server_ids: tuple[str, ...]

    @property
    def claim_count(self) -> int:
        return len(self.server_ids)


@dataclass(frozen=True)
class Corpus:
    """What one crawl decided to scan, with the cost of that decision.

    Every count here is derived from `repositories` rather than stored
    alongside it. Two crawls of the same registry must produce the same
    document, and a stored total is a second copy of a fact that can disagree
    with the first.
    """

    repositories: tuple[Repository, ...]

    @property
    def repository_count(self) -> int:
        return len(self.repositories)

    @property
    def entries_seen(self) -> int:
        """Registry entries that named a repository we could use."""
        return sum(repository.claim_count for repository in self.repositories)

    @property
    def entries_collapsed(self) -> int:
        """Entries removed by collapsing, which is what deduplication cost.

        Measured on the live registry: 25,983 entries became 20,792
        repositories, so 5,191 entries were removed. A fifth of the published
        number rather than a rounding detail. Note this counts entries
        removed, not entries involved: 5,738 entries share a repository with
        another, spread over 547 repositories, and each of those keeps one.
        """
        return self.entries_seen - self.repository_count

    @property
    def most_claimed_count(self) -> int:
        """Names on the single most-claimed repository.

        Published because it is the number that shows why collapsing is
        necessary. One account holds 2,332 names pointing at one repository.
        """
        return max(repository.claim_count for repository in self.repositories)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repositories": [
                {"repo_url": repository.repo_url, "server_ids": list(repository.server_ids)}
                for repository in self.repositories
            ]
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Corpus":
        return cls(
            repositories=tuple(
                Repository(
                    repo_url=entry["repo_url"],
                    server_ids=tuple(entry["server_ids"]),
                )
                for entry in payload["repositories"]
            )
        )


def build_corpus(records: Iterable[ServerRecord]) -> Corpus:
    """Group records by repository, so one repository is fetched once.

    This is the intake rule that moves the published number most. Scanning per
    registry entry would clone the most-claimed repository 2,332 times and then
    publish its findings as 2,332 distinct vulnerable servers, making a single
    account 9% of the index.

    Ordering is fixed here rather than left to the registry. Its page order is
    not guaranteed stable, and an unordered corpus would produce a different
    committed summary on every run while nothing had actually changed.
    """
    claims: dict[str, set[str]] = defaultdict(set)
    for record in records:
        claims[record.repo_url].add(record.server_id)

    if not claims:
        raise ValueError(
            "the crawl produced no repositories; a crawl that finds nothing is a "
            "broken upstream rather than an empty ecosystem, and publishing it "
            "would look identical to a healthy crawl of a dead ecosystem"
        )

    return Corpus(
        repositories=tuple(
            Repository(repo_url=repo_url, server_ids=tuple(sorted(server_ids)))
            for repo_url, server_ids in sorted(claims.items())
        )
    )
