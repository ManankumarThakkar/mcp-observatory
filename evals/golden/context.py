"""The source window a finding is judged from, captured once for everyone."""

import shutil
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Node

from analyzer.fetcher.clone import CloneTooLarge, FetchError
from analyzer.models import Finding
from analyzer.orchestrator import UNREACHABLE_ERRORS, CloneFn, ScanFn
from analyzer.parsing.trees import parse_source
from analyzer.rules import ALL_RULES
from analyzer.scanner import ScanReport

# Exactly the failures that mean "this repository cannot be read", and nothing
# else. Deliberately not a blind `except Exception`: the orchestrator catches
# broadly because isolating one bad repository from a corpus run is its entire
# job, but here a ValueError out of a rule is a defect, and swallowing it into
# a dropped entry would hide it among the ordinary churn of an ecosystem where
# a fifth of repositories are already deleted or private.
UNREADABLE = (CloneTooLarge, FetchError, OSError, *UNREACHABLE_ERRORS)

# Twelve lines either side of the flagged line. Measured rather than chosen: a
# first integration that sent the flagged expression alone returned nearly the
# same probability for every input, and twelve lines either side more than
# doubled the spread. Below that a judgement carries no information; well above
# it the cost rises with no measured gain.
#
# The same window reaches the human labeller and every adjudicator. If they saw
# different amounts, the benchmark would be measuring context rather than
# judgement, and the difference it reported would be unattributable.
CONTEXT_LINES = 12


@dataclass(frozen=True)
class CaptureResult:
    """The windows captured, and every entry that could not be.

    Drops are returned rather than logged because the sampler publishes the
    shortfall. A golden set that quietly ended up smaller than it claims is a
    sample whose method no longer describes it.
    """

    contexts: dict[str, str] = field(default_factory=dict)
    # The enclosing function, where one exists. Sparse on purpose: a rule the
    # manipulation does not apply to has no entry rather than a duplicate of
    # the window, which would imply an experiment that was not run on it.
    functions: dict[str, str] = field(default_factory=dict)
    dropped: dict[str, str] = field(default_factory=dict)


def capture_context(source: str, line: int, *, window: int = CONTEXT_LINES) -> str | None:
    """The `window` lines either side of a one-indexed line, or None.

    None means the line is past the end of the file, which happens because the
    clone is taken at the repository's current head and that may be many
    commits after the scan. A file that shrank is an ordinary fact about a
    moving ecosystem, so the entry is dropped rather than the run failing.

    A line below one is different and raises. Lines are one-indexed
    everywhere here, so a zero or negative one cannot come from a valid
    Location: it means a rule computed a line wrongly, and absorbing that into
    a dropped entry would hide a defect among ordinary churn.

    `splitlines` rather than `split("\\n")` so a file with carriage returns
    does not produce a window with a blank line between every line of code.
    """
    if line < 1:
        raise ValueError(f"lines are one-indexed, got {line}")

    lines = source.splitlines()
    if line > len(lines):
        return None

    # max() and min() rather than a bare slice. `line - window - 1` goes
    # negative near the top of a file, and a negative start silently returns
    # the tail instead of the head - an unrelated passage, presented to the
    # labeller as though it were the right one.
    start = max(0, line - window - 1)
    end = min(len(lines), line + window)
    return "\n".join(lines[start:end])


# Node types that count as "the function this finding lives in". Arrow
# functions and method definitions are included because an MCP tool handler is
# usually one or the other.
FUNCTION_NODES = frozenset(
    {
        "function_declaration",
        "function_expression",
        "generator_function_declaration",
        "arrow_function",
        "method_definition",
    }
)

# A function larger than this is not a judgement aid, it is a wall. Falls back
# to the line window, which at least centres on the finding.
MAX_FUNCTION_CHARS = 12_000

# Read from the rules rather than listed here, so a sixth rule arrives with its
# own answer instead of silently defaulting to the wrong one.
_NEEDS_FUNCTION = {rule.rule_id: rule.needs_enclosing_function for rule in ALL_RULES}


def capture_for_judgement(
    source: str, line: int, *, suffix: str, enclosing: bool
) -> str | None:
    """The context a reader needs to judge one finding.

    Two shapes, because two kinds of rule are judged differently.

    A taint rule - does a value an assistant supplies reach this sink? - cannot
    be judged from the sink alone. Measured while labelling: a third of
    SHELL-EXEC-UNSAFE entries were undecidable from twelve lines either side,
    and every one failed identically, with the sink visible and the origin of
    the interpolated value outside the window. The enclosing function is the
    smallest unit that contains both.

    Everything else is judged from the line and what surrounds it. A codepoint
    scan may sit in no function at all, and a wildcard origin is decided by the
    object it is declared in rather than by the call stack above it.

    Twelve lines was measured for probability spread on a decision model, which
    is a different requirement from decidability by a reader. This is the second
    requirement, measured separately.
    """
    if not enclosing:
        return capture_context(source, line)

    parsed = parse_source(source, suffix)
    if parsed is None:
        return capture_context(source, line)

    node = _enclosing_function(parsed.tree.root_node, line, source=source)
    if node is None:
        # Top-level code has no enclosing function, and dropping the entry
        # would silently shrink the sample rather than judge it.
        return capture_context(source, line)

    text = parsed.text(node)
    if len(text) > MAX_FUNCTION_CHARS:
        return capture_context(source, line)
    return text


def both_contexts(source: str, line: int, *, suffix: str) -> tuple[str | None, str | None]:
    """The same finding under both judgement conditions.

    Captured together from one clone at one commit. Capturing them in separate
    passes would let the repository move between them, which would confound the
    condition being tested with the code being judged - and the repositories in
    this corpus move daily.

    The second is None where no enclosing function exists, which is the honest
    representation of a rule the manipulation does not apply to: a document has
    no function, and carrying a duplicate of the window would imply an
    experiment that was not run on it.
    """
    narrow = capture_context(source, line)

    parsed = parse_source(source, suffix)
    if parsed is None:
        return narrow, None
    node = _enclosing_function(parsed.tree.root_node, line, source=source)
    if node is None:
        return narrow, None
    text = parsed.text(node)
    return narrow, text if len(text) <= MAX_FUNCTION_CHARS else None


def _enclosing_function(root: Node, line: int, *, source: str) -> Node | None:
    """The smallest function node that encloses a one-indexed line.

    "Encloses" rather than "overlaps", and the distinction is the whole
    function. A finding carries a line but no column, so every function node
    touching that line is a candidate, and taking the smallest then prefers a
    subexpression of the line over the scope that contains it. Measured on
    captured data: an inline `.catch(() => null)` beside a path call made ten
    characters of unrelated code the "enclosing function" for that finding, and
    forty-five of a hundred and seventeen captured functions came out smaller
    than the line window this way. Each would have reached a labeller as the
    finding's scope, producing an undecidable entry that says nothing about the
    code.

    So a candidate must begin at or before the flagged line's first
    non-whitespace character. A function that opens partway along the line is a
    fragment of it, and cannot be the scope the line sits in.

    Only the start is checked, deliberately. Every failure observed in captured
    data was a function opening mid-line; requiring it to also reach the line's
    last character instead rejected a genuine one-line handler, because the
    trailing comma in `async (args) => read(args.p),` belongs to the call around
    it rather than to the handler. Guarding a shape that has not appeared, at the
    cost of one that has, is the wrong trade. One gap remains in principle: a
    finding in the tail of a line that opens with a short unrelated function.
    Rather than assert it does not occur, the capture reports any function it
    returns that is a small fraction of its window, so that shape surfaces as a
    number instead of as a quietly undecidable entry.

    The cost is a signature line. In `server.tool("x", async (a) => {` the
    handler starts mid-line, so a finding on that line rejects it and falls back
    to the function above or to the window. That is deliberate. The failure mode
    becomes too much context rather than the wrong context, and only one of
    those quietly corrupts a judgement.
    """
    lines = source.splitlines()
    if not (1 <= line <= len(lines)):
        return None
    text = lines[line - 1]
    first = len(text) - len(text.lstrip())

    found: Node | None = None
    stack = [root]
    while stack:
        current = stack.pop()
        starts, ends = current.start_point[0] + 1, current.end_point[0] + 1
        if not (starts <= line <= ends):
            continue
        # Smallest wins among candidates that genuinely enclose the line: a
        # handler inside a factory is the useful unit.
        if (
            current.type in FUNCTION_NODES
            and _opens_at_or_before(current, line, first=first)
            and (
                found is None
                or (current.end_byte - current.start_byte)
                < (found.end_byte - found.start_byte)
            )
        ):
            found = current
        stack.extend(current.named_children)
    return found


def _opens_at_or_before(node: Node, line: int, *, first: int) -> bool:
    """Whether a node begins at or before the flagged line's first code character."""
    start_row, start_col = node.start_point
    return start_row + 1 < line or (start_row + 1 == line and start_col <= first)


def capture_for_findings(
    findings: Iterable[Finding],
    *,
    repo_urls: Mapping[str, str],
    clone: CloneFn,
    scan: ScanFn,
    workdir: Path,
) -> CaptureResult:
    """Capture each finding's window from code that still produces that finding.

    The check is the reason this is not simply "read the file and slice it".
    The repository is cloned at its current head, which may be months after
    the scan that produced these findings, so the line a finding names may now
    hold entirely different code. Labelling that would put a verdict about
    code nobody flagged into the ground truth, and nothing downstream could
    detect the substitution.

    So each repository is re-scanned and a finding is kept only if the fresh
    scan produces the same `finding_id`. That identity is deterministic over
    server, rule, path, line and evidence, and deliberately excludes the
    commit, which makes it exactly the question worth asking: is this the same
    finding, in code that has possibly moved? Re-using it beats inventing a
    comparison, and beats matching on evidence, which is a description for
    some rules and normalised source for others.

    One clone and one scan per repository, not per finding. Failures are
    recorded against the findings they cost and the capture continues:
    meeting one deleted repository three hundred clones in must not discard
    the work already done.
    """
    by_server: dict[str, list[Finding]] = {}
    for finding in findings:
        by_server.setdefault(finding.server_id, []).append(finding)

    result = CaptureResult()
    for server_id, group in sorted(by_server.items()):
        if server_id not in repo_urls:
            # The urls come from the index these findings were scanned from,
            # so a missing one means the two went out of step. Dropping it
            # quietly would shrink the sample for a reason nobody could see.
            raise KeyError(f"no repository url for {server_id}")

        destination = workdir / server_id.replace("/", "_")
        try:
            cloned = clone(repo_urls[server_id], destination)
            report = scan(cloned.path, server_id, cloned.commit_sha)
            _capture_from(cloned.path, group, report, result)
        except UNREADABLE as exc:
            for finding in group:
                result.dropped[finding.finding_id] = f"{type(exc).__name__}: {exc}"
        finally:
            # Released before the next repository is fetched. Keeping them all
            # made peak disk the sum of every repository rather than the largest
            # single one, which filled a disk part-way through a re-draw. In
            # `finally`, because the failure path is the one that fills a disk:
            # it is the path taken by whatever is wrong with the repository.
            shutil.rmtree(destination, ignore_errors=True)

    return result


def _capture_from(
    root: Path,
    group: list[Finding],
    report: ScanReport,
    result: CaptureResult,
) -> None:
    """Take each finding's window from a clone that is about to be deleted."""
    still_found = {fresh.finding_id for fresh in report.findings}
    for finding in group:
        if finding.finding_id not in still_found:
            result.dropped[finding.finding_id] = (
                "the current code no longer produces this finding, so the window "
                "at this line is not the code that was flagged"
            )
            continue

        path = root / finding.location.file
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.dropped[finding.finding_id] = f"unreadable: {exc}"
            continue

        window, enclosing = both_contexts(
            source, finding.location.line, suffix=Path(finding.location.file).suffix
        )
        if window is None:
            result.dropped[finding.finding_id] = "line is past the end of the file"
            continue
        result.contexts[finding.finding_id] = window
        # Only for the rules whose findings a window cannot settle. Carrying it
        # for the others would offer a second condition that was never tested.
        if enclosing is not None and _NEEDS_FUNCTION.get(finding.rule_id, False):
            result.functions[finding.finding_id] = enclosing

