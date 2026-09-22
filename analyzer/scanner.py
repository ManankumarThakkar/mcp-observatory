"""Walk a cloned repository and apply every rule to every scannable file."""

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from analyzer.models import Finding
from analyzer.rules import ALL_RULES
from analyzer.rules.base import FileContext

# Why a file carrying a scannable extension was not read. Deliberately does not
# cover files excluded by design, such as images or vendored dependencies: a
# skip is work we wanted to do and could not, not work we never wanted. Listing
# every asset would produce thousands of entries per server and bury the few
# that mean something.
SkipReason = Literal["symlink", "too-large", "undecodable", "unreadable"]


@dataclass(frozen=True)
class SkippedFile:
    path: str
    reason: SkipReason


@dataclass(frozen=True)
class ScanReport:
    """What a scan found, and what it could not look at.

    The second half exists because an invisible skip is the same shape of
    problem as a rule that silently does not run. The published index says a
    server was scanned; if a quarter of its source could not be read, then
    "scanned" is a claim about work that did not happen, and without this
    nothing in the output would say so.
    """

    findings: tuple[Finding, ...]
    skipped: tuple[SkippedFile, ...]

SCANNABLE_SUFFIXES = frozenset({".py", ".ts", ".js", ".tsx", ".jsx", ".json", ".md"})

# Directories holding code the repository did not write. A finding raised
# inside one of these would attribute somebody else's flaw to whoever vendored
# it, which is the same misattribution as following a symlink out of the clone.
SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__"}
)

# Largest file worth reading. The fetcher caps a whole repository at 50 MB,
# which permits one file using all of it: measured, such a file costs 23
# seconds and 235 MB of memory, and a thousand-server run of those would pass
# the CI job limit. Padding a repository is cheap, so without this the run that
# watches the ecosystem can be slowed down by the things it is watching.
#
# 1 MB is generous for source. What exceeds it is minified bundles, generated
# code and vendored blobs, none of which should be attributed to the repository
# anyway. The cost is real and recorded in DECISIONS.md: a finding inside a
# very large legitimate file goes undetected.
MAX_FILE_BYTES = 1024 * 1024


def safe_relative_path(relative: Path) -> str:
    """Render a repository path as text that can always be encoded and published.

    A filename is attacker-controlled and, on Linux, need not be valid UTF-8.
    Path decodes such bytes with surrogateescape, so the path arrives holding
    lone surrogates, and `str.encode("utf-8")` refuses those. That raised
    UnicodeEncodeError inside `finding_id`, which subclasses ValueError rather
    than OSError, so it escaped the CLI's handler and killed the whole run.

    The effect was the attacker's goal exactly: one such filename anywhere in a
    repository discarded every finding for that server, including real ones,
    leaving the repository permanently unscannable and therefore permanently
    unreported.

    Cleaned here, at the single point where a path enters the system, so the
    same value is used for the finding's identity, for its published location,
    and by every later report layer. Valid UTF-8 round-trips untouched; only
    undecodable bytes become U+FFFD, which keeps the path recognisable to
    whoever reads the finding.
    """
    return relative.as_posix().encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def scan_directory(root: Path, server_id: str, commit_sha: str) -> ScanReport:
    """Apply every rule in ALL_RULES to every scannable file under root."""
    findings: list[Finding] = []
    skipped: list[SkippedFile] = []

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
            if relative.suffix.lower() in SCANNABLE_SUFFIXES:
                skipped.append(SkippedFile(safe_relative_path(relative), "symlink"))
            continue

        if not path.is_file() or path.suffix.lower() not in SCANNABLE_SUFFIXES:
            continue

        # parent.parts rather than parts, so the check cannot be tripped by a
        # file whose own name happens to match.
        if SKIP_DIRS.intersection(relative.parent.parts):
            continue

        # Checked before reading, so an oversized file costs a stat rather than
        # the memory to hold it. Safe to stat here because symlinks were
        # already excluded above.
        try:
            oversized = path.stat().st_size > MAX_FILE_BYTES
        except OSError:
            skipped.append(SkippedFile(safe_relative_path(relative), "unreadable"))
            continue
        if oversized:
            skipped.append(SkippedFile(safe_relative_path(relative), "too-large"))
            continue

        try:
            # utf-8-sig rather than utf-8: a UTF-8 BOM is an encoding artefact,
            # and plain utf-8 leaves it in the string as U+FEFF, where
            # UNICODE-CONCEAL would score it critical. Every BOM-prefixed file
            # in the corpus would otherwise be a false positive.
            source = path.read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            # One file we cannot decode is not a reason to abandon the
            # repository. Undecodable files carrying source extensions are
            # ordinary in the wild rather than suspicious, and on a nightly run
            # a single one must not cost us every finding in that server. It is
            # recorded rather than dropped, because coverage is a published
            # claim.
            skipped.append(SkippedFile(safe_relative_path(relative), "undecodable"))
            continue
        except OSError:
            skipped.append(SkippedFile(safe_relative_path(relative), "unreadable"))
            continue

        ctx = FileContext(
            server_id=server_id,
            commit_sha=commit_sha,
            relative_path=safe_relative_path(relative),
            source=source,
        )
        for rule in ALL_RULES:
            findings.extend(rule.analyze(ctx))

    # Sorted rather than walk-ordered, so two scans of one repository produce
    # the same document and a diff always means the repository changed.
    return ScanReport(
        findings=tuple(findings),
        skipped=tuple(sorted(skipped, key=lambda s: (s.path, s.reason))),
    )
