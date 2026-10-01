import json
import shutil
from pathlib import Path

import pytest

from analyzer.cli import main
from analyzer.report import history_store
from analyzer.report.history_store import HistoryRefused, restore_history, save_history

KEY = "c" * 64
NIGHT_ONE = "2026-10-02T03:20:00Z"
NIGHT_TWO = "2026-10-03T03:20:00Z"


def _copy(source: Path, target: Path, passphrase: str) -> None:
    """Stands in for gpg, so the restore rules are tested without it."""
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


@pytest.fixture(autouse=True)
def _no_gpg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(history_store, "unseal", _copy)
    monkeypatch.setattr(history_store, "seal", _copy)


def _sealed(tmp_path: Path, *last_seen: str) -> Path:
    path = tmp_path / "history.jsonl.gpg"
    path.write_text(
        "".join(json.dumps({"finding_id": f"f-{n}", "last_seen": s}) + "\n" for n, s in enumerate(last_seen))
    )
    return path


def _trend(tmp_path: Path, *scanned_at: str) -> Path:
    path = tmp_path / "trend.jsonl"
    path.write_text(
        "".join(
            json.dumps(
                {
                    "scanned_at": s, "corpus": 1, "scanned": 1, "findings_found": 1,
                    "findings_published": 0, "withheld": 1, "servers_affected": 1, "by_rule": {},
                }
            )
            + "\n"
            for s in scanned_at
        )
    )
    return path


def test_a_sealed_history_matching_the_last_trend_point_is_restored(tmp_path: Path) -> None:
    history = tmp_path / "cache" / "history.jsonl"
    restore_history(
        _sealed(tmp_path, NIGHT_ONE, NIGHT_TWO), history, _trend(tmp_path, NIGHT_ONE, NIGHT_TWO),
        key=KEY, bootstrap=False,
    )
    assert len(history.read_text().splitlines()) == 2


def test_a_missing_history_is_refused_rather_than_started_empty(tmp_path: Path) -> None:
    # Starting empty would silently erase every disclosure window in it.
    history = tmp_path / "cache" / "history.jsonl"
    with pytest.raises(HistoryRefused, match="bootstrap"):
        restore_history(
            tmp_path / "missing.gpg", history, _trend(tmp_path, NIGHT_ONE), key=KEY, bootstrap=False
        )
    assert not history.exists()


def test_a_first_night_starts_empty_only_when_asked_to(tmp_path: Path) -> None:
    history = tmp_path / "cache" / "history.jsonl"
    restore_history(tmp_path / "missing.gpg", history, _trend(tmp_path, NIGHT_ONE), key=KEY, bootstrap=True)
    assert history.read_text() == ""


def test_bootstrapping_over_an_existing_history_is_refused(tmp_path: Path) -> None:
    history = tmp_path / "cache" / "history.jsonl"
    with pytest.raises(HistoryRefused, match="would discard"):
        restore_history(
            _sealed(tmp_path, NIGHT_ONE), history, _trend(tmp_path, NIGHT_ONE), key=KEY, bootstrap=True
        )
    assert not history.exists()


def test_an_older_history_than_the_series_is_refused_as_a_rollback(tmp_path: Path) -> None:
    # The history and the series are saved in one commit, so their last nights
    # always match. A mismatch means one was replaced with an older copy.
    history = tmp_path / "cache" / "history.jsonl"
    with pytest.raises(HistoryRefused, match="rolled back"):
        restore_history(
            _sealed(tmp_path, NIGHT_ONE), history, _trend(tmp_path, NIGHT_ONE, NIGHT_TWO),
            key=KEY, bootstrap=False,
        )
    assert not history.exists(), "a refused history was left where the scan would read it"


def test_no_key_is_refused(tmp_path: Path) -> None:
    with pytest.raises(HistoryRefused, match="HISTORY_KEY"):
        restore_history(
            _sealed(tmp_path, NIGHT_ONE), tmp_path / "h.jsonl", _trend(tmp_path, NIGHT_ONE),
            key="", bootstrap=False,
        )


def test_saving_seals_the_history(tmp_path: Path) -> None:
    history = tmp_path / "history.jsonl"
    history.write_text('{"finding_id": "f-1"}\n')
    save_history(history, tmp_path / "out" / "history.jsonl.gpg", key=KEY)
    assert (tmp_path / "out" / "history.jsonl.gpg").exists()


def test_the_command_reads_the_key_from_the_environment_and_refuses_in_a_sentence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("HISTORY_KEY", KEY)
    args = [
        "history", "restore", "--sealed", str(tmp_path / "missing.gpg"),
        "--history", str(tmp_path / "h.jsonl"), "--trend", str(_trend(tmp_path, NIGHT_ONE)),
    ]
    assert main(args) != 0
    assert "bootstrap" in capsys.readouterr().err
    assert main([*args, "--bootstrap"]) == 0
    assert (tmp_path / "h.jsonl").exists()
