import base64
import random
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from analyzer.report import vault
from analyzer.report.vault import VaultError, seal, unseal

pytestmark = pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg is not installed")

KEY = "a" * 64


def _plain(tmp_path: Path) -> Path:
    # Random, so it barely compresses. With compressible text a flipped byte
    # breaks decompression and gpg writes nothing, which hides the case that
    # matters: damage landing in literal data, where gpg writes the whole
    # altered plaintext and only its exit code says anything is wrong.
    path = tmp_path / "history.jsonl"
    path.write_bytes(base64.b64encode(random.Random(20261001).randbytes(150_000)))
    return path


def _flip(path: Path, at: int) -> None:
    data = bytearray(path.read_bytes())
    data[at] ^= 1
    path.write_bytes(bytes(data))


def test_a_sealed_history_opens_to_the_same_bytes(tmp_path: Path) -> None:
    plain = _plain(tmp_path)
    seal(plain, tmp_path / "history.jsonl.gpg", KEY)
    unseal(tmp_path / "history.jsonl.gpg", tmp_path / "opened.jsonl", KEY)
    assert (tmp_path / "opened.jsonl").read_bytes() == plain.read_bytes()


@pytest.mark.parametrize("where", ["middle", "end"])
def test_a_tampered_history_is_refused_and_leaves_nothing_behind(
    tmp_path: Path, where: str
) -> None:
    # Measured: gpg reports "message has been manipulated" and exits 2, but
    # still writes the whole altered plaintext. Only the exit code protects us.
    sealed = tmp_path / "history.jsonl.gpg"
    seal(_plain(tmp_path), sealed, KEY)
    size = sealed.stat().st_size
    _flip(sealed, size // 2 if where == "middle" else size - 5)
    opened = tmp_path / "out" / "history.jsonl"
    opened.parent.mkdir()
    with pytest.raises(VaultError):
        unseal(sealed, opened, KEY)
    assert list(opened.parent.iterdir()) == [], "a refused unseal left a file behind"


def _gpg_that_writes_then_fails(arguments: list[str], passphrase: str) -> None:
    """gpg as measured on a manipulated message: full output, then exit 2."""
    output = Path(arguments[arguments.index("--output") + 1])
    output.write_text("manipulated plaintext\n", encoding="utf-8")
    raise VaultError("gpg exited 2: WARNING: encrypted message has been manipulated!")


def test_output_from_a_failed_gpg_run_is_discarded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(vault, "_gpg", _gpg_that_writes_then_fails)
    opened = tmp_path / "out" / "history.jsonl"
    opened.parent.mkdir()
    with pytest.raises(VaultError):
        unseal(tmp_path / "history.jsonl.gpg", opened, KEY)
    assert list(opened.parent.iterdir()) == []


def test_a_refused_unseal_never_replaces_the_history_already_there(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(vault, "_gpg", _gpg_that_writes_then_fails)
    existing = tmp_path / "current.jsonl"
    existing.write_text("tonight's good history\n", encoding="utf-8")
    with pytest.raises(VaultError):
        unseal(tmp_path / "history.jsonl.gpg", existing, KEY)
    assert existing.read_text(encoding="utf-8") == "tonight's good history\n"


def test_the_wrong_key_is_refused(tmp_path: Path) -> None:
    sealed = tmp_path / "history.jsonl.gpg"
    seal(_plain(tmp_path), sealed, KEY)
    with pytest.raises(VaultError):
        unseal(sealed, tmp_path / "opened.jsonl", "b" * 64)
    assert not (tmp_path / "opened.jsonl").exists()


def test_the_key_never_appears_in_gpg_s_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Arguments are visible to every process on the machine; stdin is not.
    seen: list[list[str]] = []
    real_run = subprocess.run

    def recording_run(args: list[str], **kwargs: Any) -> Any:
        seen.append([str(a) for a in args])
        return real_run(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", recording_run)
    seal(_plain(tmp_path), tmp_path / "history.jsonl.gpg", KEY)
    unseal(tmp_path / "history.jsonl.gpg", tmp_path / "opened.jsonl", KEY)
    assert seen, "gpg was never called"
    assert not any(KEY in arg for args in seen for arg in args)


def test_sealing_refuses_a_ciphertext_that_does_not_open_to_its_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A bad write must fail tonight, not surface as a lost history tomorrow.
    def corrupting_unseal(sealed: Path, plaintext: Path, passphrase: str) -> None:
        plaintext.write_text("not what was sealed\n", encoding="utf-8")

    monkeypatch.setattr(vault, "unseal", corrupting_unseal)
    target = tmp_path / "history.jsonl.gpg"
    with pytest.raises(VaultError, match="does not open to"):
        seal(_plain(tmp_path), target, KEY)
    assert not target.exists()


@pytest.mark.parametrize("key", ["", "two\nlines"])
def test_a_key_gpg_would_misread_is_refused(tmp_path: Path, key: str) -> None:
    # gpg reads one line from the descriptor, so an empty key or one with a
    # newline would silently seal with a different key than the one stored.
    with pytest.raises(ValueError, match="key"):
        seal(_plain(tmp_path), tmp_path / "history.jsonl.gpg", key)


def test_a_saved_history_restores_through_real_gpg_and_agrees_with_its_series(
    tmp_path: Path,
) -> None:
    from analyzer.report.history_store import restore_history, save_history

    stamp = "2026-10-02T03:20:00Z"
    history = tmp_path / "history.jsonl"
    history.write_text(f'{{"finding_id": "f-1", "last_seen": "{stamp}"}}\n', encoding="utf-8")
    trend = tmp_path / "trend.jsonl"
    trend.write_text(
        '{"scanned_at": "' + stamp + '", "corpus": 1, "scanned": 1, "findings_found": 1, '
        '"findings_published": 0, "withheld": 1, "servers_affected": 1, "by_rule": {}}\n',
        encoding="utf-8",
    )
    save_history(history, tmp_path / "history.jsonl.gpg", key=KEY)
    restored = tmp_path / "cache" / "history.jsonl"
    restore_history(tmp_path / "history.jsonl.gpg", restored, trend, key=KEY, bootstrap=False)
    assert restored.read_bytes() == history.read_bytes()


def test_a_history_that_was_never_encrypted_is_refused(tmp_path: Path) -> None:
    # Measured: `gpg --store` writes an unencrypted message that `--decrypt`
    # accepts with exit 0, no key needed. A clean exit is therefore not proof
    # of anything; anyone able to push the file could plant a history.
    planted = tmp_path / "planted.jsonl"
    planted.write_text('{"finding_id": "planted"}\n', encoding="utf-8")
    sealed = tmp_path / "history.jsonl.gpg"
    home = tmp_path / "g"
    home.mkdir(mode=0o700)
    subprocess.run(
        ["gpg", "--homedir", str(home), "--batch", "--quiet", "--store", "-o", str(sealed), str(planted)],
        check=True,
        capture_output=True,
    )
    opened = tmp_path / "out" / "history.jsonl"
    opened.parent.mkdir()
    with pytest.raises(VaultError, match="not decrypted"):
        unseal(sealed, opened, KEY)
    assert list(opened.parent.iterdir()) == []


def test_a_partial_file_gpg_leaves_behind_is_swept_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Measured on gpg 2.5: it writes to "<output>.part" and renames at the end,
    # and on some failures leaves the .part file - partial plaintext of the
    # confidential history - beside the target.
    def gpg_that_leaves_a_part_file(arguments: list[str], passphrase: str) -> list[str]:
        output = Path(arguments[arguments.index("--output") + 1])
        output.with_name(output.name + ".part").write_text("partial plaintext\n", encoding="utf-8")
        raise VaultError("gpg exited 2: decompression failed")

    monkeypatch.setattr(vault, "_gpg", gpg_that_leaves_a_part_file)
    opened = tmp_path / "out" / "history.jsonl"
    opened.parent.mkdir()
    with pytest.raises(VaultError):
        unseal(tmp_path / "history.jsonl.gpg", opened, KEY)
    assert list(opened.parent.iterdir()) == []
