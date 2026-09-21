"""Retrieve a repository for static analysis, without ever running it."""

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

# Only transports that fetch bytes. Deliberately excludes ssh and git, whose
# helper commands are configurable through the environment, and ext, which
# exists to run an arbitrary command. http is excluded as plaintext.
ALLOWED_SCHEMES = frozenset({"https", "file"})

# Backstops, not a budget. Git offers no reliable way to learn a repository's
# size before fetching it, so by the time these fire the bytes have already
# crossed the wire. The real pre-filter belongs in the crawler, which reads the
# host API's reported size and can decline to enqueue an oversized repository.
MAX_BYTES = 50 * 1024 * 1024
MAX_FILES = 5_000


class FetchError(Exception):
    """Base for fetch failures that are expected outcomes rather than bugs.

    A caller can distinguish these from a genuine defect: the CLI reports them
    as ordinary errors instead of a traceback, and the orchestrator records
    them against the server and carries on with the rest of the run.
    """


class UnsupportedRepositoryURL(FetchError):
    """Raised for a repository URL we are not willing to hand to git."""


class CloneTooLarge(FetchError):
    """Raised when a cloned repository exceeds the configured resource caps."""


class DestinationNotEmpty(FetchError):
    """Raised when the target directory already holds something."""


@dataclass(frozen=True)
class CloneResult:
    path: Path
    commit_sha: str


def _require_supported_url(repo_url: str) -> None:
    """Reject a hostile URL before any subprocess starts.

    Repository URLs arrive from a third-party registry, so they are attacker
    influenced. Git will execute a command named in an `ext::` URL, and the
    obvious mitigation does not hold: the legacy GIT_ALLOW_PROTOCOL environment
    variable takes precedence over `-c protocol.ext.allow=never`, so config
    hardening alone leaves the door open in an environment we do not control.

    An allowlist applied before git is invoked does not depend on the
    environment, which is why it is the primary defence rather than a
    secondary one.
    """
    scheme = urlparse(repo_url).scheme
    if scheme not in ALLOWED_SCHEMES:
        raise UnsupportedRepositoryURL(
            f"refusing {repo_url!r}: scheme {scheme or '(none)'} is not one of "
            f"{', '.join(sorted(ALLOWED_SCHEMES))}"
        )


def _safe_environment() -> dict[str, str]:
    """The environment git runs in, constructed rather than inherited.

    Git takes a great deal of behaviour from its environment, and several of
    those variables name a command it will execute: GIT_SSH_COMMAND,
    GIT_PROXY_COMMAND and GIT_EXTERNAL_DIFF among them. GIT_ALLOW_PROTOCOL can
    re-enable the `ext` transport, whose entire purpose is running a command,
    and GIT_CONFIG_COUNT injects arbitrary configuration.

    GIT_ALLOW_PROTOCOL in particular **overrides `-c protocol.ext.allow=never`
    on the command line**, verified against git 2.39. So config hardening is not
    sufficient on its own, and inheriting the ambient environment would leave
    the never-execute invariant at the mercy of whatever a CI image happens to
    set. Constructing the environment removes the entire class rather than
    naming variables to strip, which would need updating for every new one.
    """
    return {
        # git must still be findable.
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        # Never block a nightly run waiting for credentials on a private repo.
        "GIT_TERMINAL_PROMPT": "0",
        # Ignore /etc/gitconfig, and point HOME away from ~/.gitconfig. Neither
        # belongs to this process, and both can name commands.
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": "/nonexistent",
    }


def _git(args: list[str], *, cwd: Path, timeout_s: int) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        timeout=timeout_s,
        capture_output=True,
        text=True,
        env=_safe_environment(),
    )


def _require_empty_destination(dest: Path) -> None:
    """Refuse a destination that already holds something.

    Git would otherwise fail inside `git remote add` with exit 128 and a
    message naming an internal command, which across a nightly run over a
    thousand repositories is far harder to diagnose than a sentence saying
    what is wrong. Requiring an empty directory also removes any chance of
    measuring, or later scanning, content left by an earlier run as though it
    had just been fetched.
    """
    if dest.exists() and any(dest.iterdir()):
        raise DestinationNotEmpty(
            f"refusing to clone into {dest}: the directory is not empty. "
            "Each clone needs a fresh directory, so that nothing left by an "
            "earlier run can be mistaken for what was just fetched."
        )


def _fetched_bytes(dest: Path) -> int:
    """Size of the object store after fetch, before a working tree exists."""
    objects = dest / ".git" / "objects"
    return sum(p.stat().st_size for p in objects.rglob("*") if p.is_file())


def _enforce_caps(root: Path) -> None:
    """Measure the checked-out tree, counting only what the repository owns.

    Symlinks are counted as entries but contribute no bytes, and are never
    followed. A repository may legally contain a link pointing anywhere on the
    host, and `is_file()` and `stat()` both follow one: a link to a large file
    elsewhere would be measured as part of the repository, and a link to
    anything readable would aim our traversal at it. Counting the link itself
    still bounds a repository made of nothing but links.
    """
    total_bytes = 0
    file_count = 0

    for path in root.rglob("*"):
        if ".git" in path.parts:
            continue

        # Tested before is_file(), which follows the link and would report True
        # for a symlink pointing at a regular file outside the clone.
        is_link = path.is_symlink()
        if not is_link and not path.is_file():
            continue

        file_count += 1
        if file_count > MAX_FILES:
            raise CloneTooLarge(f"exceeded {MAX_FILES} files")

        if is_link:
            continue

        # lstat rather than stat: identical for a non-symlink, and it keeps the
        # measurement correct if the entry is swapped for a link between the
        # check above and this line.
        total_bytes += path.lstat().st_size
        if total_bytes > MAX_BYTES:
            raise CloneTooLarge(f"exceeded {MAX_BYTES} bytes")


def shallow_clone(repo_url: str, dest: Path, *, timeout_s: int = 60) -> CloneResult:
    """Clone the default branch at depth 1. Never installs, builds or executes.

    Reports the commit it actually received rather than fetching a
    caller-supplied SHA. Fetching an arbitrary SHA requires the remote to set
    uploadpack.allowAnySHA1InWant, which is not universal. Recording what
    arrived is equally reproducible and depends on nothing the server opts in
    to.
    """
    _require_supported_url(repo_url)
    _require_empty_destination(dest)

    dest.mkdir(parents=True, exist_ok=True)
    try:
        _git(["init", "-q"], cwd=dest, timeout_s=timeout_s)
        _git(["remote", "add", "origin", repo_url], cwd=dest, timeout_s=timeout_s)
        _git(["fetch", "--depth", "1", "-q", "origin", "HEAD"], cwd=dest, timeout_s=timeout_s)

        # Checked before checkout. At this point the repository is on disk
        # once; after checkout it is on disk twice. Aborting here halves what
        # an oversized repository costs us.
        fetched = _fetched_bytes(dest)
        if fetched > MAX_BYTES:
            raise CloneTooLarge(f"fetched {fetched} bytes, exceeded {MAX_BYTES} bytes")

        _git(["checkout", "-q", "FETCH_HEAD"], cwd=dest, timeout_s=timeout_s)
        _enforce_caps(dest)

        sha = _git(["rev-parse", "HEAD"], cwd=dest, timeout_s=timeout_s).stdout.strip()
    except BaseException:
        # Anything that goes wrong leaves a partial clone behind, and a nightly
        # run over a thousand repositories would fill the volume with debris
        # from the failures long before anyone read the individual errors.
        # BaseException rather than Exception because a timeout or an interrupt
        # leaves the most on disk, and it is re-raised immediately either way.
        # The destination was required to be empty, so nothing removed here
        # belonged to the caller.
        shutil.rmtree(dest, ignore_errors=True)
        raise

    return CloneResult(path=dest, commit_sha=sha)
