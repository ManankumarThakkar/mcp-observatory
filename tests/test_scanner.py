import json
from pathlib import Path

import pytest

from analyzer.cli import main
from analyzer.models import Finding, Location
from analyzer.rules.base import FileContext
from analyzer.scanner import MAX_FILE_BYTES, SkippedFile, scan_directory


class _recorder:
    """A rule that records the contexts it was handed and finds nothing."""

    rule_id = "TEST-RECORDER"

    def __init__(self, seen: list[FileContext]) -> None:
        self._seen = seen

    def analyze(self, ctx: FileContext) -> list[Finding]:
        self._seen.append(ctx)
        return []

TAG_CHAR = "\U000e0041"  # TAG LATIN CAPITAL LETTER A, invisible to a reader


def test_scan_finds_concealed_unicode_in_a_nested_file(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "server.py").write_text(
        f'description = "reads files{TAG_CHAR}"\n', encoding="utf-8"
    )
    (tmp_path / "README.md").write_text("Ordinary documentation.\n", encoding="utf-8")

    findings = scan_directory(tmp_path, server_id="owner/repo", commit_sha="c" * 40).findings

    assert len(findings) == 1
    assert findings[0].location.file == "src/server.py"
    assert findings[0].server_id == "owner/repo"


def test_paths_are_reported_relative_to_the_repository_root(tmp_path: Path) -> None:
    """Findings are published, so an absolute path would leak the scanning
    host's directory layout into a public report."""
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    (nested / "c.py").write_text(f'x = "{TAG_CHAR}"\n', encoding="utf-8")

    findings = scan_directory(tmp_path, server_id="owner/repo", commit_sha="c" * 40).findings

    assert findings[0].location.file == "a/b/c.py"


def test_vendored_directories_are_not_scanned(tmp_path: Path) -> None:
    """Third-party code vendored into a repository is not that repository's.

    Scanning it attributes somebody else's flaw to whoever vendored it, which
    is the same misattribution as the symlink case below and just as public.
    """
    for directory in ("node_modules/pkg", "__pycache__", ".git", "dist"):
        vendored = tmp_path / directory
        vendored.mkdir(parents=True)
        (vendored / "index.js").write_text(f'const d = "{TAG_CHAR}";\n', encoding="utf-8")

    assert scan_directory(tmp_path, server_id="owner/repo", commit_sha="d" * 40).findings == ()


def test_a_symlink_pointing_outside_the_clone_is_never_read(tmp_path: Path) -> None:
    """A hostile repository can name a symlink so it looks like its own file.

    Both the filename and the link are legal git content. Following it reads a
    file belonging to the scanning host and attributes whatever is in it to the
    repository being scanned, in a finding that gets published. Rules arriving
    in Plan 2 quote source into evidence, at which point the file's contents
    are published too.
    """
    outside = tmp_path / "host"
    outside.mkdir()
    (outside / "id_rsa").write_text(f"PRIVATE KEY{TAG_CHAR}\n", encoding="utf-8")

    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "config.py").symlink_to(outside / "id_rsa")

    findings = scan_directory(repo, server_id="victim/repo", commit_sha="d" * 40).findings

    assert findings == (), "content from outside the clone reached a published finding"


def test_a_directory_symlink_is_not_traversed(tmp_path: Path) -> None:
    """Skipped explicitly rather than relying on rglob.

    Python 3.12 happens not to recurse into directory symlinks, but that is
    behaviour rather than a guarantee, and 3.13 made it configurable.
    """
    outside = tmp_path / "host"
    outside.mkdir()
    (outside / "secret.py").write_text(f'k = "{TAG_CHAR}"\n', encoding="utf-8")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "vendored").symlink_to(outside, target_is_directory=True)

    assert scan_directory(repo, server_id="owner/repo", commit_sha="d" * 40).findings == ()


def test_a_broken_symlink_does_not_stop_the_scan(tmp_path: Path) -> None:
    """One unreadable entry must not cost us the rest of the repository."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "dangling.py").symlink_to(tmp_path / "does-not-exist.py")
    (repo / "real.py").write_text(f'x = "{TAG_CHAR}"\n', encoding="utf-8")

    findings = scan_directory(repo, server_id="owner/repo", commit_sha="d" * 40).findings

    assert len(findings) == 1
    assert findings[0].location.file == "real.py"


def test_a_binary_file_with_a_scannable_extension_does_not_stop_the_scan(
    tmp_path: Path,
) -> None:
    """A .json that is not text is ordinary in the wild, not an attack.

    One undecodable file must not cost us the rest of the repository, and on a
    nightly run it must not cost us the repository entirely.
    """
    (tmp_path / "data.json").write_bytes(b"\x00\xff\xfe not really json")
    (tmp_path / "real.py").write_text(f'x = "{TAG_CHAR}"\n', encoding="utf-8")

    findings = scan_directory(tmp_path, server_id="owner/repo", commit_sha="e" * 40).findings

    assert len(findings) == 1
    assert findings[0].location.file == "real.py"


def test_an_unreadable_file_does_not_stop_the_scan(tmp_path: Path) -> None:
    import os

    if os.geteuid() == 0:
        pytest.skip("running as root, permissions do not apply")

    unreadable = tmp_path / "locked.py"
    unreadable.write_text("x = 1\n", encoding="utf-8")
    unreadable.chmod(0o000)
    (tmp_path / "real.py").write_text(f'x = "{TAG_CHAR}"\n', encoding="utf-8")

    try:
        findings = scan_directory(tmp_path, server_id="owner/repo", commit_sha="e" * 40).findings
    finally:
        unreadable.chmod(0o644)  # so pytest can clean the directory up

    assert len(findings) == 1
    assert findings[0].location.file == "real.py"


def test_a_byte_order_mark_does_not_become_a_finding(tmp_path: Path) -> None:
    """Read as utf-8-sig, so the BOM never reaches a rule as U+FEFF.

    The rule ignores a leading BOM too. Both layers are deliberate: this one
    is the correct place to handle an encoding artefact, and the rule's own
    check keeps it correct for any other caller.
    """
    (tmp_path / "server.py").write_bytes(b'\xef\xbb\xbfdescription = "Reads a file."\n')

    assert scan_directory(tmp_path, server_id="owner/repo", commit_sha="e" * 40).findings == ()


def test_an_uppercase_extension_is_still_scanned(tmp_path: Path) -> None:
    """Suffix matching is case sensitive, and case-insensitive filesystems
    hide that until the scan runs on Linux against a repository holding
    server.PY."""
    (tmp_path / "SERVER.PY").write_text(f'x = "{TAG_CHAR}"\n', encoding="utf-8")

    findings = scan_directory(tmp_path, server_id="owner/repo", commit_sha="e" * 40).findings

    assert len(findings) == 1


def test_cli_scans_a_local_path_and_writes_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "server.py").write_text(f'd = "{TAG_CHAR}"\n', encoding="utf-8")

    exit_code = main(["scan", "--path", str(tmp_path), "--server-id", "owner/repo"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["server_id"] == "owner/repo"
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["rule_id"] == "UNICODE-CONCEAL"


def test_a_clean_scan_still_emits_valid_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Finding nothing is a result, not a failure.

    The nightly pipeline consumes this output, so a clean server has to
    produce a parseable document and exit zero like any other.
    """
    (tmp_path / "server.py").write_text("x = 1\n", encoding="utf-8")

    exit_code = main(["scan", "--path", str(tmp_path), "--server-id", "owner/repo"])

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["findings"] == []


def test_a_missing_path_is_reported_clearly_and_prints_no_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["scan", "--path", str(tmp_path / "nope"), "--server-id", "owner/repo"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "nope" in captured.err
    assert captured.out == "", "a failed run must not emit a partial document"


def test_a_rejected_url_surfaces_as_a_clean_error_not_a_traceback(
    capsys: pytest.CaptureFixture[str]
) -> None:
    """The URL allowlist is a security control, so its refusal is an ordinary
    outcome the CLI reports, not an internal error the user has to decode."""
    exit_code = main(["scan", "--repo-url", "ext::sh -c 'x'", "--server-id", "owner/repo"])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "ext" in captured.err
    assert captured.out == ""


def test_a_file_over_the_size_cap_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Scanning cost is bounded per file, not only per repository.

    The fetcher caps a repository at 50 MB, which allows one file using all of
    it. Measured, that file takes 23 seconds and 235 MB of memory to scan, so a
    thousand-server run of such repositories would exceed the CI job limit.
    Padding a repository is cheap, which makes it a cheap way to slow down the
    run that is supposed to be watching you.
    """
    monkeypatch.setattr("analyzer.scanner.MAX_FILE_BYTES", 64)

    oversized = tmp_path / "huge.py"
    oversized.write_text(f'# {"padding " * 40}\nd = "{TAG_CHAR}"\n', encoding="utf-8")
    assert oversized.stat().st_size > 64

    assert scan_directory(tmp_path, server_id="owner/repo", commit_sha="f" * 40).findings == ()


def test_a_file_within_the_size_cap_is_still_scanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The counterpart: the cap must not be so eager it skips ordinary files."""
    monkeypatch.setattr("analyzer.scanner.MAX_FILE_BYTES", 64)

    small = tmp_path / "small.py"
    small.write_text(f'd = "{TAG_CHAR}"\n', encoding="utf-8")
    assert small.stat().st_size <= 64

    assert len(scan_directory(tmp_path, server_id="owner/repo", commit_sha="f" * 40).findings) == 1


def test_an_oversized_file_does_not_stop_the_rest_of_the_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("analyzer.scanner.MAX_FILE_BYTES", 64)

    (tmp_path / "huge.py").write_text("# " + "padding " * 40 + "\n", encoding="utf-8")
    (tmp_path / "real.py").write_text(f'd = "{TAG_CHAR}"\n', encoding="utf-8")

    findings = scan_directory(tmp_path, server_id="owner/repo", commit_sha="f" * 40).findings

    assert len(findings) == 1
    assert findings[0].location.file == "real.py"


def test_an_undecodable_filename_cannot_destroy_a_whole_scan() -> None:
    """A single byte in a filename must not hide every finding in a repository.

    On Linux a filename may contain bytes that are not valid UTF-8. Path
    decodes them with surrogateescape, so the path arrives as a string holding
    lone surrogates, and `str.encode("utf-8")` refuses those. That raises
    UnicodeEncodeError inside finding_id, which subclasses ValueError rather
    than OSError, so the CLI's handler did not catch it.

    The result was the attacker's goal exactly: put one such filename anywhere
    in a repository, and the scan of every other file succeeds and is then
    thrown away when serialisation dies. The repository becomes permanently
    unscannable, and therefore permanently unreported, on a public risk index.
    """
    from analyzer.scanner import safe_relative_path

    cleaned = safe_relative_path(Path("src/decoy\udcff.py"))

    finding = Finding(
        server_id="owner/repo",
        commit_sha="a" * 40,
        rule_id="UNICODE-CONCEAL",
        severity="critical",
        confidence="high",
        location=Location(file=cleaned, line=1),
        evidence="zero-width-space U+200B at line 1",
    )

    assert json.loads(json.dumps(finding.to_dict()))["location"]["file"] == cleaned
    assert finding.finding_id


def test_legitimate_non_ascii_paths_are_left_alone() -> None:
    """The cleaning must not mangle paths that are perfectly valid."""
    from analyzer.scanner import safe_relative_path

    for path in ("src/server.py", "src/服务器.py", "src/café.py"):
        assert safe_relative_path(Path(path)) == path


def test_an_oversized_file_is_reported_rather_than_dropped(tmp_path: Path) -> None:
    """An invisible skip is the same shape of problem as a rule that never ran.

    The published index says a server was scanned. If a quarter of its source
    was silently too large to read, "scanned" is a claim about work that did
    not happen, and nothing in the output would say so.
    """
    (tmp_path / "huge.py").write_text("x" * (MAX_FILE_BYTES + 1), encoding="utf-8")

    report = scan_directory(tmp_path, server_id="owner/repo", commit_sha="a" * 40)

    assert report.skipped == (SkippedFile(path="huge.py", reason="too-large"),)


def test_an_undecodable_file_is_reported(tmp_path: Path) -> None:
    (tmp_path / "binary.py").write_bytes(b"\xff\xfe\x00\x01not text")

    report = scan_directory(tmp_path, server_id="owner/repo", commit_sha="a" * 40)

    assert report.skipped == (SkippedFile(path="binary.py", reason="undecodable"),)


def test_a_symlink_is_reported(tmp_path: Path) -> None:
    """Worth reporting rather than merely worth refusing.

    A link pointing out of the repository is how a hostile repository tries to
    get a file from the scanning host attributed to itself. We decline to
    follow it, and saying that we declined is more useful than silence.
    """
    (tmp_path / "real.py").write_text("print('hi')\n", encoding="utf-8")
    (tmp_path / "link.py").symlink_to(tmp_path / "real.py")

    report = scan_directory(tmp_path, server_id="owner/repo", commit_sha="a" * 40)

    assert report.skipped == (SkippedFile(path="link.py", reason="symlink"),)


def test_files_excluded_by_design_are_not_reported_as_skips(tmp_path: Path) -> None:
    """A skip is work we wanted to do and could not, not work we never wanted.

    Reporting every image, lockfile and vendored dependency would produce
    thousands of entries per server and bury the handful that mean something.
    """
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n")
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text("module.exports = {}\n", encoding="utf-8")

    report = scan_directory(tmp_path, server_id="owner/repo", commit_sha="a" * 40)

    assert report.skipped == ()


def test_skips_are_ordered_so_two_scans_of_one_repository_match(tmp_path: Path) -> None:
    for name in ("c.py", "a.py", "b.py"):
        (tmp_path / name).write_bytes(b"\xff\xfe bad")

    report = scan_directory(tmp_path, server_id="owner/repo", commit_sha="a" * 40)

    assert [s.path for s in report.skipped] == ["a.py", "b.py", "c.py"]


def test_a_python_file_reaches_a_rule_already_parsed(tmp_path: Path) -> None:
    """Parsing happens once per file, not once per rule.

    Four rules will want the same tree. Parsing in the walk and handing the
    result down keeps the cost at one parse per file rather than one per rule.
    """
    (tmp_path / "server.py").write_text("def handler():\n    pass\n", encoding="utf-8")
    seen: list[FileContext] = []

    scan_directory(
        tmp_path,
        server_id="owner/repo",
        commit_sha="a" * 40,
        rules=(_recorder(seen),),
    )

    assert len(seen) == 1
    assert seen[0].parsed is not None
    assert seen[0].parsed.language == "python"


def test_a_file_with_no_grammar_reaches_a_rule_unparsed(tmp_path: Path) -> None:
    """Markdown still reaches the codepoint rule, which needs no tree at all."""
    (tmp_path / "README.md") .write_text("hidden text\n", encoding="utf-8")
    seen: list[FileContext] = []

    scan_directory(
        tmp_path,
        server_id="owner/repo",
        commit_sha="a" * 40,
        rules=(_recorder(seen),),
    )

    assert len(seen) == 1
    assert seen[0].parsed is None


def test_a_file_that_cannot_be_parsed_is_reported(tmp_path: Path) -> None:
    """A tree full of errors is a rule that silently finds nothing.

    Every other reason a file went unexamined is reported. A file whose
    grammar could not read it is the same kind of gap, and leaving it out
    would overstate what the deeper rules actually covered.
    """
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    report = scan_directory(tmp_path, server_id="owner/repo", commit_sha="a" * 40)

    assert report.skipped == (SkippedFile(path="broken.py", reason="unparsable"),)


def test_an_unparsable_file_still_reaches_every_rule(tmp_path: Path) -> None:
    """Reporting a gap must not create one.

    The tree is partial rather than absent, and the rules that need no tree
    are unaffected, so dropping the file would lose real coverage in order to
    report that coverage was lost.
    """
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    seen: list[FileContext] = []

    report = scan_directory(
        tmp_path,
        server_id="owner/repo",
        commit_sha="a" * 40,
        rules=(_recorder(seen),),
    )

    assert [ctx.relative_path for ctx in seen] == ["broken.py"]
    assert report.skipped == (SkippedFile(path="broken.py", reason="unparsable"),)
