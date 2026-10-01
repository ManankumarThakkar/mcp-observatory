"""Seal and unseal the findings history, which holds withheld findings.

The repository is public, so the history can only be stored next to the
published series if it is encrypted. `gpg --symmetric` is used because it is
preinstalled on the CI runner and its format carries an integrity check.

That check does not by itself fail closed, and a clean exit is not proof
either. Measured on 2026-10-01:
- given a ciphertext with one byte flipped, gpg reports that the message was
  manipulated and exits 2, yet still writes the whole altered plaintext;
- given a file that was never encrypted (`gpg --store`), gpg "decrypts" it with
  exit 0 and no key at all.
So nothing gpg writes is used unless it exited cleanly and its status lines
show a real decryption with integrity protection.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

GPG_TIMEOUT_SECONDS = 120


class VaultError(RuntimeError):
    """gpg refused, or a result could not be verified. Nothing was written."""


def _check_key(passphrase: str) -> None:
    # gpg reads exactly one line from the descriptor, so an empty key or one
    # holding a newline would quietly seal with a key other than the one stored.
    if not passphrase or "\n" in passphrase or "\r" in passphrase:
        raise ValueError("the history key must be one non-empty line")


def _gpg(arguments: list[str], passphrase: str) -> list[str]:
    """Run gpg with the key on stdin, never in its arguments.

    Returns gpg's machine-readable status lines, written to stdout because the
    data itself always goes to a file.

    Arguments are readable by every process on the machine. A private home
    directory under /tmp keeps the run away from any real keyring and short
    enough for gpg's agent socket: on macOS the default temporary directory is
    long enough that the agent fails with "File name too long".
    """
    home = tempfile.mkdtemp(prefix="g", dir="/tmp")
    try:
        result = subprocess.run(
            [
                "gpg",
                "--homedir",
                home,
                "--batch",
                "--quiet",
                "--yes",
                "--no-tty",
                "--no-symkey-cache",
                "--pinentry-mode",
                "loopback",
                "--passphrase-fd",
                "0",
                "--status-fd",
                "1",
                *arguments,
            ],
            input=passphrase + "\n",
            capture_output=True,
            text=True,
            timeout=GPG_TIMEOUT_SECONDS,
            check=False,
        )
    finally:
        # The agent gpg starts exits by itself once its socket is gone, about
        # five seconds after this (measured). An explicit `gpgconf --kill` cost
        # 1.2 seconds a call. Running with no agent at all is not an option:
        # gpg then exits 2 even on success, which would make the exit code
        # meaningless.
        shutil.rmtree(home, ignore_errors=True)
    if result.returncode != 0:
        reason = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "no message"
        raise VaultError(f"gpg exited {result.returncode}: {reason}")
    return [
        line.removeprefix("[GNUPG:] ")
        for line in result.stdout.splitlines()
        if line.startswith("[GNUPG:] ")
    ]


def _require_decrypted(status: list[str]) -> None:
    """Refuse output that gpg did not actually decrypt with integrity protection.

    DECRYPTION_INFO carries the integrity method and the AEAD algorithm; one of
    them must be non-zero, or the file could have been altered undetectably.
    """
    keywords = {line.split()[0]: line.split()[1:] for line in status if line.split()}
    info = keywords.get("DECRYPTION_INFO", [])
    protected = bool(info) and (info[0] != "0" or (len(info) > 2 and info[2] != "0"))
    if not ("BEGIN_DECRYPTION" in keywords and "DECRYPTION_OKAY" in keywords and protected):
        raise VaultError(
            "the file was not decrypted with integrity protection, so it may not be a "
            "sealed history at all"
        )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _temporary_beside(path: Path) -> Path:
    """A fresh name in the destination's directory, so the final rename is atomic."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    os.close(handle)
    os.unlink(name)
    return Path(name)


def unseal(sealed: Path, plaintext: Path, passphrase: str) -> None:
    """Decrypt `sealed` into `plaintext`, or raise and leave `plaintext` untouched."""
    _check_key(passphrase)
    staged = _temporary_beside(plaintext)
    try:
        status = _gpg(["--decrypt", "--output", str(staged), str(sealed)], passphrase)
        _require_decrypted(status)
        os.replace(staged, plaintext)
    finally:
        staged.unlink(missing_ok=True)


def seal(plaintext: Path, sealed: Path, passphrase: str) -> None:
    """Encrypt `plaintext` into `sealed`, proving it opens again before keeping it.

    A ciphertext that does not decrypt back to its input fails tonight, while
    tonight's history still exists, rather than tomorrow as a lost history.
    """
    _check_key(passphrase)
    staged = _temporary_beside(sealed)
    check = _temporary_beside(plaintext)
    try:
        _gpg(
            ["--symmetric", "--cipher-algo", "AES256", "--output", str(staged), str(plaintext)],
            passphrase,
        )
        unseal(staged, check, passphrase)
        if _sha256(check) != _sha256(plaintext):
            raise VaultError(f"the sealed history does not open to {plaintext.name}")
        os.replace(staged, sealed)
    finally:
        staged.unlink(missing_ok=True)
        check.unlink(missing_ok=True)
