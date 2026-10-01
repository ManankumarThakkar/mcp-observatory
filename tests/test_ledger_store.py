import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from analyzer.report.ledger import Notice, OptOut
from analyzer.report.ledger_store import LEDGER_BRANCH, fetch_ledger, publish_ledger

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is not installed")

KEY = "d" * 64
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout


def _clone_of_empty_origin(tmp_path: Path) -> tuple[Path, Path]:
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True, capture_output=True)
    _git(clone, "config", "user.email", "test@example.com")
    _git(clone, "config", "user.name", "Test")
    return origin, clone


def _notice(server: str = "acme/notes") -> Notice:
    return Notice(
        server_id=server,
        finding_ids=("f-1",),
        channel="private_advisory",
        notified_at=NOW,
        reference="email",
        verified_by="manan",
    )


def test_a_first_ledger_creates_the_branch_holding_only_ciphertext(tmp_path: Path) -> None:
    origin, clone = _clone_of_empty_origin(tmp_path)
    entries, parent = fetch_ledger(clone, key=KEY)
    assert (entries, parent) == ([], None)

    publish_ledger(clone, [_notice()], key=KEY, parent=parent)

    files = _git(origin, "ls-tree", "--name-only", LEDGER_BRANCH).split()
    assert files == ["ledger.jsonl.gpg"]
    sealed = subprocess.run(
        ["git", "-C", str(origin), "show", f"{LEDGER_BRANCH}:ledger.jsonl.gpg"],
        check=True,
        capture_output=True,
    ).stdout
    assert b"acme/notes" not in sealed, "the ledger reached a public branch in plain text"


def test_the_branch_grows_on_top_of_what_is_there(tmp_path: Path) -> None:
    origin, clone = _clone_of_empty_origin(tmp_path)
    publish_ledger(clone, [_notice()], key=KEY, parent=None)
    entries, parent = fetch_ledger(clone, key=KEY)
    publish_ledger(
        clone, [*entries, OptOut(server_id="other/server", requested_at=NOW)], key=KEY, parent=parent
    )

    entries, _ = fetch_ledger(clone, key=KEY)
    assert entries == [_notice(), OptOut(server_id="other/server", requested_at=NOW)]
    assert _git(origin, "rev-list", "--count", LEDGER_BRANCH).strip() == "2"


def test_a_ledger_moved_since_it_was_read_is_not_overwritten(tmp_path: Path) -> None:
    # Never forced: a second writer's notice must not be erased by a stale copy.
    _, clone = _clone_of_empty_origin(tmp_path)
    publish_ledger(clone, [_notice()], key=KEY, parent=None)
    _, stale_parent = fetch_ledger(clone, key=KEY)
    entries, parent = fetch_ledger(clone, key=KEY)
    publish_ledger(clone, [*entries, _notice("b/two")], key=KEY, parent=parent)

    with pytest.raises(subprocess.CalledProcessError):
        publish_ledger(clone, [_notice(), _notice("c/three")], key=KEY, parent=stale_parent)
    entries, _ = fetch_ledger(clone, key=KEY)
    assert [e.server_id for e in entries] == ["acme/notes", "b/two"]


def test_commit_messages_name_no_server(tmp_path: Path) -> None:
    # The branch is public; which servers have unfixed problems is not.
    origin, clone = _clone_of_empty_origin(tmp_path)
    publish_ledger(clone, [_notice("secret/server")], key=KEY, parent=None)
    assert "secret/server" not in _git(origin, "log", "--format=%B", LEDGER_BRANCH)


def test_an_unreachable_origin_is_refused_not_read_as_an_empty_ledger(tmp_path: Path) -> None:
    # Reading a network failure as "no ledger" would start a new one and, with
    # nothing to build on, lose every notice already recorded.
    _, clone = _clone_of_empty_origin(tmp_path)
    _git(clone, "remote", "set-url", "origin", str(tmp_path / "nowhere.git"))
    with pytest.raises(subprocess.CalledProcessError):
        fetch_ledger(clone, key=KEY)
