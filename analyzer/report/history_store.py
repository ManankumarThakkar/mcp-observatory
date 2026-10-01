"""Carry the findings history from one nightly run to the next, sealed.

The rules here are what make the store fail closed. A history that cannot be
restored exactly is refused, never replaced by an empty one, because an empty
history silently erases every disclosure window it held.
"""

import json
from pathlib import Path

from analyzer.report.trend import load_trend
from analyzer.report.vault import seal, unseal


class HistoryRefused(RuntimeError):
    """The history could not be trusted, so nothing was restored."""


def _require_key(key: str) -> None:
    if not key:
        raise HistoryRefused("HISTORY_KEY is not set, so the history cannot be opened")


def _newest_last_seen(history: Path) -> str | None:
    stamps = [
        str(json.loads(line).get("last_seen", ""))
        for line in history.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return max(stamps) if stamps else None


def restore_history(
    sealed: Path, history: Path, trend: Path, *, key: str, bootstrap: bool
) -> str:
    """Open last night's sealed history where tonight's scan will read it.

    `bootstrap` is the only way to start from nothing, and it is refused when a
    sealed history exists, because starting over would discard it.

    The history and the series are committed together, so the newest night in
    one is the last point in the other. A mismatch means one of them was
    replaced with an older copy, and the restored file is removed so the scan
    cannot read it.
    """
    _require_key(key)
    if not sealed.exists():
        if not bootstrap:
            raise HistoryRefused(
                f"no sealed history at {sealed}; start from nothing only by running "
                "with bootstrap, and only on the first night"
            )
        history.parent.mkdir(parents=True, exist_ok=True)
        history.write_text("", encoding="utf-8")
        return "no sealed history; starting from nothing, as asked"
    if bootstrap:
        raise HistoryRefused(
            f"a sealed history exists at {sealed}; bootstrapping would discard it"
        )

    points = load_trend(trend)
    if not points:
        raise HistoryRefused(
            f"a sealed history exists but there is no series at {trend} to check it "
            "against; the two are always saved together"
        )
    unseal(sealed, history, key)
    newest = _newest_last_seen(history)
    if newest is not None and newest != points[-1].scanned_at:
        history.unlink()
        raise HistoryRefused(
            f"the history ends at {newest} but the series ends at {points[-1].scanned_at}; "
            "one of them was rolled back"
        )
    return f"restored the history up to {newest or 'an empty history'}"


def save_history(history: Path, sealed: Path, *, key: str) -> None:
    """Seal tonight's history for the next run to restore."""
    _require_key(key)
    seal(history, sealed, key)
