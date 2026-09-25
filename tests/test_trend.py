import json
from pathlib import Path

import pytest

from analyzer.report.trend import TrendPoint, append_point, load_trend

POINT = TrendPoint(
    scanned_at="2026-09-25T00:00:00Z",
    corpus=21492,
    scanned=1643,
    findings_found=1296,
    findings_published=323,
    withheld=973,
    servers_affected=145,
    by_rule={"SCOPE-OVERBROAD": 323},
)


def test_a_point_is_appended_rather_than_replacing_the_series(tmp_path: Path) -> None:
    """The series is the deliverable. A run that rewrote the file would destroy
    every earlier night, and no earlier night can be recreated.
    """
    path = tmp_path / "trend.jsonl"

    append_point(path, POINT)
    append_point(path, TrendPoint(**{**POINT.__dict__, "scanned_at": "2026-09-26T00:00:00Z"}))

    assert len(load_trend(path)) == 2


def test_two_runs_on_one_day_replace_rather_than_duplicate(tmp_path: Path) -> None:
    """A re-run after a failure is one night's measurement taken twice, not two
    nights. Two points for one date would show a spike or a flat step that never
    happened, and a trend that lies is worse than a trend with a gap.
    """
    path = tmp_path / "trend.jsonl"

    append_point(path, POINT)
    append_point(path, TrendPoint(**{**POINT.__dict__, "findings_found": 1400}))

    series = load_trend(path)
    assert len(series) == 1
    assert series[0].findings_found == 1400


def test_the_series_is_ordered_by_date_however_it_was_written(tmp_path: Path) -> None:
    """A backfilled or out-of-order run must not put a later date before an
    earlier one, because a chart drawn in file order would read as a reversal.
    """
    path = tmp_path / "trend.jsonl"

    append_point(path, TrendPoint(**{**POINT.__dict__, "scanned_at": "2026-09-27T00:00:00Z"}))
    append_point(path, TrendPoint(**{**POINT.__dict__, "scanned_at": "2026-09-25T00:00:00Z"}))

    assert [p.scanned_at[:10] for p in load_trend(path)] == ["2026-09-25", "2026-09-27"]


def test_a_missing_series_is_empty_rather_than_an_error(tmp_path: Path) -> None:
    """The first night has no predecessor, and failing there would mean the job
    can never run a first time."""
    assert load_trend(tmp_path / "absent.jsonl") == []


def test_a_corrupt_line_names_its_number_rather_than_being_skipped(tmp_path: Path) -> None:
    """A silently dropped point is a gap in a published trend that nobody can
    see - the same reason the findings history refuses to skip a bad line."""
    path = tmp_path / "trend.jsonl"
    path.write_text(json.dumps(POINT.__dict__) + "\nnot json\n", encoding="utf-8")

    with pytest.raises(ValueError, match="line 2"):
        load_trend(path)


def test_a_point_with_no_date_is_refused(tmp_path: Path) -> None:
    """A point that cannot be placed in time is not a point in a time series."""
    with pytest.raises(ValueError, match="scanned_at"):
        append_point(tmp_path / "t.jsonl", TrendPoint(**{**POINT.__dict__, "scanned_at": ""}))


def test_the_file_stays_readable_as_it_grows(tmp_path: Path) -> None:
    """One line per night for years is still a small file, and one object per
    line means a reader can append without parsing the whole thing."""
    path = tmp_path / "trend.jsonl"
    for day in range(1, 29):
        append_point(path, TrendPoint(**{**POINT.__dict__, "scanned_at": f"2026-09-{day:02d}T00:00:00Z"}))

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 28
    assert all(json.loads(line)["corpus"] == 21492 for line in lines)


def test_a_point_is_derived_from_the_published_data(tmp_path: Path) -> None:
    """The point must describe what was published, not be assembled by hand.
    Two descriptions of one night would eventually disagree, and the trend would
    disagree with the page it sits on.
    """
    from analyzer.report.trend import point_from_site
    from tests.conftest import SITE

    point = point_from_site(SITE)

    assert point.scanned_at == SITE.generated_at
    assert point.corpus == SITE.corpus
    assert point.findings_published == SITE.findings_published
    assert point.withheld == SITE.withheld
    assert point.by_rule["SCOPE-OVERBROAD"] == 322
