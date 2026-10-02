import json
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from analyzer import cli
from analyzer.cli import main
from analyzer.crawler.http import Opener, Response
from analyzer.models import Finding, Location
from analyzer.report.vault import seal

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is not installed")

KEY = "a1" * 32
FINDING = Finding(
    server_id="acme/notes",
    commit_sha="c" * 40,
    rule_id="PATH-TRAVERSAL",
    severity="critical",
    confidence="high",
    location=Location(file="src/files.ts", line=3),
    evidence="fs.readFile(args.path)",
)


def _git(repo: Path, *args: str, stdin: str | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], input=stdin, check=True, capture_output=True, text=True
    ).stdout


def _no_private_channel(token: str) -> Opener:
    def opener(url: str) -> Response:
        if url.endswith("/private-vulnerability-reporting"):
            return Response(status=200, headers={}, body=b'{"enabled": false}')
        return Response(status=404, headers={}, body=b'{"message": "Not Found"}')

    return opener


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", str(origin)], check=True)
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True, capture_output=True)
    _git(clone, "config", "user.email", "test@example.com")
    _git(clone, "config", "user.name", "Test")
    plain, sealed = tmp_path / "history.jsonl", tmp_path / "history.jsonl.gpg"
    stamp = "2026-10-02T03:20:00Z"
    plain.write_text(json.dumps({**FINDING.to_dict(), "first_seen": stamp, "last_seen": stamp}) + "\n")
    seal(plain, sealed, KEY)
    blob = _git(clone, "hash-object", "-w", str(sealed)).strip()
    tree = _git(clone, "mktree", stdin=f"100644 blob {blob}\thistory.jsonl.gpg\n").strip()
    _git(clone, "push", "-q", "origin", f"{_git(clone, 'commit-tree', tree, '-m', 't').strip()}:refs/heads/nightly-data")

    cache = clone / ".cache"
    (cache / "annotations").mkdir(parents=True)
    (cache / "golden-entries.jsonl").write_text(
        json.dumps({"entry_id": "g-1", "finding_id": FINDING.finding_id}) + "\n"
    )
    (cache / "annotations" / "manan.jsonl").write_text(
        json.dumps({"entry_id": "g-1", "label": "true_positive", "reason": "joined unchecked", "annotator": "manan"})
        + "\n"
    )
    (cache / "server_index.jsonl").write_text(
        json.dumps({"server_id": "acme/notes", "repo_url": "https://github.com/acme/notes", "discovered_via": "registry"})
        + "\n"
    )
    monkeypatch.chdir(clone)
    monkeypatch.setenv("HISTORY_KEY", KEY)
    monkeypatch.setenv("GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(cli, "authorised_opener", _no_private_channel)
    return clone


def test_a_private_draft_is_written_and_the_screen_names_no_server(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["notices", "--annotator", "manan"]) == 0
    out_dir = repo / ".cache" / "notices"
    assert stat.S_IMODE(out_dir.stat().st_mode) == 0o700, "drafts hold vulnerability details"
    draft = (out_dir / "acme--notes.md").read_text()
    assert f"https://github.com/acme/notes/blob/{'c' * 40}/src/files.ts#L3" in draft
    assert "joined unchecked" in draft
    printed = capsys.readouterr().out
    assert "1 draft" in printed
    assert "acme/notes" not in printed


def test_a_server_with_no_private_channel_also_gets_the_contact_request(repo: Path) -> None:
    main(["notices", "--annotator", "manan"])
    request = (repo / ".cache" / "notices" / "acme--notes.contact.md").read_text()
    assert "security contact" in request.lower()
    assert "src/files.ts" not in request


def test_without_a_github_token_the_channel_check_is_refused_not_skipped(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("GITHUB_TOKEN")
    assert main(["notices", "--annotator", "manan"]) != 0
    assert "GITHUB_TOKEN" in capsys.readouterr().err
