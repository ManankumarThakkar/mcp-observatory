"""The time series: one small point per night, appended.

Spec section 12 said the git history of `data/` would provide the time series.
This replaces that, and the change is deliberate.

Reading a trend out of commit history requires archaeology nobody performs, so
the figure that nothing else in this field publishes would have existed in
principle and been unavailable in practice. An explicit file is readable by the
dashboard, by a script and by a person.

It also keeps nightly machine output out of a reviewed history. `main` requires
pull requests, and the project already refused to commit `corpus.json` because a
nightly run would produce thousands of diff lines nobody reads. A daily line of
counts is the smallest thing that answers "is this getting safer".
"""

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from analyzer.report.site import SiteData


@dataclass(frozen=True)
class TrendPoint:
    """One night's measurement, as small as it can be and still mean something.

    Counts only. The findings themselves live in `data/`, which is reviewed and
    published separately; duplicating them here would make the series large
    enough that nobody keeps it and would put the same fact in two places.
    """

    scanned_at: str
    corpus: int
    scanned: int
    findings_found: int
    findings_published: int
    withheld: int
    servers_affected: int
    by_rule: dict[str, int] = field(default_factory=dict)


def _day(point_or_stamp: str) -> str:
    return point_or_stamp[:10]


def load_trend(path: Path) -> list[TrendPoint]:
    """The whole series, oldest first.

    Sorted by date rather than trusted in file order. A backfilled or
    out-of-order run would otherwise put a later date before an earlier one, and
    a chart drawn in file order would read as a reversal that never happened.

    A corrupt line raises with its number rather than being skipped, for the
    reason the findings history gives: a silently dropped point is a gap in a
    published trend that nobody can see.
    """
    if not path.exists():
        return []

    points: list[TrendPoint] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            points.append(TrendPoint(**json.loads(line)))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"{path} is unreadable at line {number}: {exc}") from exc

    return sorted(points, key=lambda point: point.scanned_at)


def append_point(path: Path, point: TrendPoint) -> None:
    """Add tonight's measurement, replacing any earlier one for the same day.

    Replacing rather than appending twice, because a re-run after a failure is
    one night's measurement taken again, not two nights. Two points for one date
    would draw a spike or a flat step that never happened, and a trend that lies
    is worse than a trend with a gap.

    The whole file is rewritten rather than appended to, which costs nothing at
    one line a night and is what makes the same-day replacement possible.
    """
    if not point.scanned_at:
        raise ValueError("a point with no scanned_at cannot be placed in a time series")

    kept = [p for p in load_trend(path) if _day(p.scanned_at) != _day(point.scanned_at)]
    series = sorted([*kept, point], key=lambda p: p.scanned_at)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(asdict(p), sort_keys=True) + "\n" for p in series),
        encoding="utf-8",
    )


def point_from_site(site: "SiteData") -> TrendPoint:
    """Tonight's point, derived from the data the page shows.

    Derived rather than assembled separately, so the trend and the page cannot
    disagree about one night. Two descriptions of the same measurement is the
    shape of a bug that only appears once somebody compares them.
    """
    return TrendPoint(
        scanned_at=site.generated_at,
        corpus=site.corpus,
        scanned=site.scanned,
        findings_found=site.findings_found,
        findings_published=site.findings_published,
        withheld=site.withheld,
        servers_affected=site.servers_affected,
        by_rule={rule.rule_id: rule.findings for rule in site.rules},
    )
