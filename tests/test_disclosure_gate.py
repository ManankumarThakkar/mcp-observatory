from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from analyzer.models import Finding, Location, Severity
from analyzer.report.gate import (
    DISCLOSURE_WINDOW,
    GATED_SEVERITIES,
    DisclosureRecord,
    disclosure_state,
    split_for_publication,
)

NOW = datetime(2026, 9, 20, tzinfo=UTC)


def _finding(severity: str = "critical", server_id: str = "owner/repo") -> Finding:
    return Finding(
        server_id=server_id,
        commit_sha="a" * 40,
        rule_id="UNICODE-CONCEAL",
        severity=cast(Severity, severity),
        confidence="high",
        location=Location(file="src/index.ts", line=1),
        evidence="unicode-tag-block U+E0041",
    )


def _record(**kwargs: object) -> DisclosureRecord:
    defaults: dict[str, object] = {
        "server_id": "owner/repo",
        "notified_at": None,
        "opted_out": False,
    }
    return DisclosureRecord(**{**defaults, **kwargs})  # type: ignore[arg-type]


# --- the four states ----------------------------------------------------------

def test_an_opted_out_maintainer_is_honoured_before_anything_else() -> None:
    """Spec section 14 makes opt-out unconditional.

    Checked first, so it cannot become conditional on severity, on whether a
    notification was sent, or on how long ago it was.
    """
    for severity in ("critical", "high", "medium", "low", "info"):
        state = disclosure_state(
            _finding(severity=severity), _record(opted_out=True), now=NOW
        )
        assert state == "opted_out", severity


def test_a_serious_finding_nobody_has_been_told_about_is_withheld() -> None:
    """The window opens at notification, so an un-notified finding has no window."""
    assert disclosure_state(_finding("critical"), _record(), now=NOW) == "withheld"
    assert disclosure_state(_finding("high"), _record(), now=NOW) == "withheld"


def test_a_serious_finding_inside_the_window_is_withheld() -> None:
    record = _record(notified_at=NOW - DISCLOSURE_WINDOW + timedelta(days=1))

    assert disclosure_state(_finding("critical"), record, now=NOW) == "withheld"


def test_a_serious_finding_past_the_window_may_be_published() -> None:
    record = _record(notified_at=NOW - DISCLOSURE_WINDOW - timedelta(seconds=1))

    assert disclosure_state(_finding("critical"), record, now=NOW) == "disclosed"


def test_the_window_boundary_is_not_a_publication() -> None:
    """Exactly 90 days is not more than 90 days.

    An off-by-one here publishes a day early, which is the one direction this
    gate must never be wrong in.
    """
    record = _record(notified_at=NOW - DISCLOSURE_WINDOW)

    assert disclosure_state(_finding("critical"), record, now=NOW) == "withheld"


def test_a_lesser_finding_publishes_immediately() -> None:
    for severity in ("medium", "low", "info"):
        assert disclosure_state(_finding(severity), _record(), now=NOW) == "published"


def test_only_the_gated_severities_wait() -> None:
    """Derived from the constant so changing it cannot silently pass."""
    assert GATED_SEVERITIES == frozenset({"critical", "high"})


# --- failing closed -----------------------------------------------------------

def test_a_server_with_no_record_at_all_is_withheld() -> None:
    """Absence of a record is not evidence that anyone was notified."""
    published, _ = split_for_publication([_finding("critical")], {}, now=NOW)

    assert published == []


def test_a_notification_dated_in_the_future_does_not_open_the_window() -> None:
    """Bad data must not publish. A future date means the window has not run."""
    record = _record(notified_at=NOW + timedelta(days=365))

    assert disclosure_state(_finding("critical"), record, now=NOW) == "withheld"


def test_a_naive_timestamp_is_refused_rather_than_compared() -> None:
    """Comparing a naive datetime to an aware one raises deep inside a run.

    Refusing at the boundary turns an obscure TypeError during a nightly
    publish into a clear failure at the point the bad value entered.
    """
    # The naive datetimes below are the subject of the test, not an oversight:
    # DTZ001 exists to stop them reaching production code, and proving the
    # guard rejects one means constructing one here.
    with pytest.raises(ValueError, match="timezone"):
        disclosure_state(
            _finding("critical"),
            _record(notified_at=datetime(2026, 1, 1)),  # noqa: DTZ001
            now=NOW,
        )

    with pytest.raises(ValueError, match="timezone"):
        disclosure_state(
            _finding("critical"), _record(), now=datetime(2026, 1, 1)  # noqa: DTZ001
        )


# --- splitting a run ----------------------------------------------------------

def test_only_disclosed_and_lesser_findings_reach_the_published_list() -> None:
    """The invariant this whole task exists for.

    Spec section 11: a finding cannot reach data/ in a publishable state
    without passing this gate.
    """
    findings = [
        _finding("critical", "a/withheld"),
        _finding("critical", "b/disclosed"),
        _finding("critical", "c/optedout"),
        _finding("medium", "d/lesser"),
        _finding("high", "e/unknown"),
    ]
    records = {
        "a/withheld": _record(server_id="a/withheld", notified_at=NOW - timedelta(days=5)),
        "b/disclosed": _record(
            server_id="b/disclosed", notified_at=NOW - DISCLOSURE_WINDOW - timedelta(days=1)
        ),
        "c/optedout": _record(server_id="c/optedout", opted_out=True),
    }

    published, counts = split_for_publication(findings, records, now=NOW)

    assert [f.server_id for f in published] == ["b/disclosed", "d/lesser"]
    assert counts == {"withheld": 2, "disclosed": 1, "opted_out": 1, "published": 1}


def test_the_counts_publish_even_when_the_findings_do_not() -> None:
    """Spec section 11: aggregate statistics publish immediately.

    The dashboard can say "2 findings withheld pending disclosure" without
    naming a server, which is the point of returning a count beside the list.
    """
    findings = [_finding("critical", "a/one"), _finding("critical", "b/two")]

    published, counts = split_for_publication(findings, {}, now=NOW)

    assert published == []
    assert counts["withheld"] == 2


def test_an_empty_run_produces_empty_counts_for_every_state() -> None:
    """A caller reading counts should never have to guard a missing key."""
    published, counts = split_for_publication([], {}, now=NOW)

    assert published == []
    assert counts == {"withheld": 0, "disclosed": 0, "opted_out": 0, "published": 0}


def test_publication_order_follows_the_input() -> None:
    findings = [_finding("low", "c/one"), _finding("low", "a/two"), _finding("low", "b/three")]

    published, _ = split_for_publication(findings, {}, now=NOW)

    assert [f.server_id for f in published] == ["c/one", "a/two", "b/three"]
