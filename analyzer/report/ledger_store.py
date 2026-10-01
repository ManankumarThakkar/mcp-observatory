"""Keep the sealed ledger on its own branch, written only from the maintainer's machine.

One writer per file. The nightly force-pushes `nightly-data` every night, so a
notice recorded there mid-run could be overwritten; here the nightly only
reads. The ledger is written with plumbing commands, so the caller's checkout
and index are never touched, and pushed without force, so a copy that is out
of date is rejected rather than erasing a notice recorded since.
"""

import shutil
import subprocess
import tempfile
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from analyzer.report.ledger import Entry, load_ledger, write_ledger
from analyzer.report.vault import seal, unseal

LEDGER_BRANCH = "disclosure-ledger"
LEDGER_FILE = "ledger.jsonl.gpg"

# `git ls-remote --exit-code` exits 2 when the remote answered and has no such
# branch, and with another code when it could not be reached at all.
NO_SUCH_BRANCH = 2


def _git(repo: Path, *args: str, stdin: str | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        input=stdin,
        check=True,
        capture_output=True,
        text=True,
    ).stdout


@contextmanager
def _private_dir() -> Iterator[Path]:
    """Somewhere only this user can read, for the plaintext, removed afterwards."""
    path = Path(tempfile.mkdtemp(prefix="ledger", dir="/tmp"))
    path.chmod(0o700)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def fetch_ledger(repo: Path, *, key: str) -> tuple[list[Entry], str | None]:
    """The ledger as the remote holds it, and the commit to build on.

    A branch that does not exist yet is an empty ledger. A remote that cannot
    be reached raises: reading that as empty would start a new ledger and drop
    every notice already recorded.
    """
    probe = subprocess.run(
        ["git", "-C", str(repo), "ls-remote", "--exit-code", "origin", f"refs/heads/{LEDGER_BRANCH}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode == NO_SUCH_BRANCH:
        return [], None
    if probe.returncode != 0:
        raise subprocess.CalledProcessError(probe.returncode, probe.args, probe.stdout, probe.stderr)
    head = probe.stdout.split()[0]
    _git(repo, "fetch", "-q", "origin", f"refs/heads/{LEDGER_BRANCH}")
    sealed_bytes = subprocess.run(
        ["git", "-C", str(repo), "show", f"{head}:{LEDGER_FILE}"],
        check=True,
        capture_output=True,
    ).stdout
    with _private_dir() as work:
        (work / LEDGER_FILE).write_bytes(sealed_bytes)
        unseal(work / LEDGER_FILE, work / "ledger.jsonl", key)
        return load_ledger(work / "ledger.jsonl"), head


def publish_ledger(
    repo: Path, entries: Sequence[Entry], *, key: str, parent: str | None
) -> str:
    """Seal the ledger and push it as one commit on top of `parent`.

    The commit message gives only a count. The branch is public, and which
    servers have unfixed problems is exactly what the ledger keeps private.
    """
    with _private_dir() as work:
        write_ledger(work / "ledger.jsonl", entries)
        seal(work / "ledger.jsonl", work / LEDGER_FILE, key)
        blob = _git(repo, "hash-object", "-w", str(work / LEDGER_FILE)).strip()
    tree = _git(repo, "mktree", stdin=f"100644 blob {blob}\t{LEDGER_FILE}\n").strip()
    parents = ["-p", parent] if parent else []
    commit = _git(
        repo, "commit-tree", tree, *parents, "-m", f"ledger: {len(entries)} entries"
    ).strip()
    _git(repo, "push", "-q", "origin", f"{commit}:refs/heads/{LEDGER_BRANCH}")
    return commit
