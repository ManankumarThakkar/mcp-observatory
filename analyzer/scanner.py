"""Walk a cloned repository and apply every rule to every scannable file."""

from pathlib import Path

from analyzer.models import Finding
from analyzer.rules import ALL_RULES
from analyzer.rules.base import FileContext

SCANNABLE_SUFFIXES = frozenset({".py", ".ts", ".js", ".tsx", ".jsx", ".json", ".md"})

# Directories holding code the repository did not write. A finding raised
# inside one of these would attribute somebody else's flaw to whoever vendored
# it, which is the same misattribution as following a symlink out of the clone.
SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
)


def scan_directory(root: Path, server_id: str, commit_sha: str) -> list[Finding]:
    """Apply every rule in ALL_RULES to every scannable file under root."""
    findings: list[Finding] = []

    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)

        # Symlinks are never followed, in either direction, and this is tested
        # before is_file() because is_file() follows the link and reports True.
        #
        # Outward, a link is how a hostile repository reads a file belonging to
        # the scanning host and has its contents attributed to itself in a
        # published finding. Inward, a link targets a file already scanned by
        # its real path, so following it gains no coverage and costs a
        # duplicate finding under a second name with a different finding_id.
        #
        # Directory links are covered by the same check. Python 3.12 happens
        # not to recurse into them, but that is behaviour rather than a
        # guarantee, and 3.13 made it configurable.
        if path.is_symlink():
            continue

        if not path.is_file() or path.suffix.lower() not in SCANNABLE_SUFFIXES:
            continue

        # parent.parts rather than parts, so the check cannot be tripped by a
        # file whose own name happens to match.
        if SKIP_DIRS.intersection(relative.parent.parts):
            continue

        try:
            # utf-8-sig rather than utf-8: a UTF-8 BOM is an encoding artefact,
            # and plain utf-8 leaves it in the string as U+FEFF, where
            # UNICODE-CONCEAL would score it critical. Every BOM-prefixed file
            # in the corpus would otherwise be a false positive.
            source = path.read_text(encoding="utf-8-sig")
        except (UnicodeDecodeError, OSError):
            # One file we cannot decode or open is not a reason to abandon the
            # repository. Undecodable files carrying source extensions are
            # ordinary in the wild rather than suspicious, and on a nightly run
            # a single one must not cost us every finding in that server.
            continue
        ctx = FileContext(
            server_id=server_id,
            commit_sha=commit_sha,
            relative_path=relative.as_posix(),
            source=source,
        )
        for rule in ALL_RULES:
            findings.extend(rule.analyze(ctx))

    return findings
