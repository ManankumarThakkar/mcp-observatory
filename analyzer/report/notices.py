"""Draft private notices to maintainers, one per server, from verified findings.

The tool drafts and a person sends. A draft is a starting point to be read and
reworked, never something to paste unread: it carries vulnerability details,
so it is written only to a private local directory and never printed whole.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from analyzer.report.channels import ChannelSuggestion
from analyzer.report.gate import DISCLOSURE_WINDOW
from analyzer.report.ledger import WINDOW_CHANNELS, Entry, Notice, OptOut
from analyzer.rules import ALL_RULES

REWORK_MARK = "[REWORK BEFORE SENDING: written for the labeller, not the maintainer]"

# Why each rule's finding can matter, and the safe pattern to move to. Plain
# language for a maintainer, with no exploit and no proof of concept
# (SECURITY.md). Keyed by every rule, so a new rule without text fails a test.
NOTICE_TEXT: dict[str, tuple[str, str]] = {
    "PATH-TRAVERSAL": (
        ("An MCP server's tools are called by an AI assistant, and the assistant's"
        " arguments can be steered by any text it reads, such as a web page, a file or"
        " an issue. A path taken from a tool argument and used without a check lets"
        " that text choose which file the server reads or writes, with the server's"
        " own privileges on the user's machine."),
        ("Resolve the path against a fixed base directory, then refuse it unless the"
        " resolved path still lies inside that directory (for example, compare"
        " `path.resolve(base, input)` against `base` after resolving both). Refuse"
        " absolute paths and symbolic links that leave the base."),
    ),
    "SHELL-EXEC-UNSAFE": (
        ("A tool argument that reaches a shell command lets whatever steers the"
        " assistant's arguments run commands on the user's machine with the server's"
        " privileges. The assistant's arguments can be influenced by any text it reads."),
        ("Avoid the shell: call the program directly with its arguments as a list (for"
        " example `execFile` or `spawn` without `shell: true`), and accept only values"
        " from a fixed set where the argument chooses an action."),
    ),
    "TOOL-DESC-INJECTION": (
        ("A tool's description is read by the AI assistant as instructions. Text in it"
        " that tells the assistant what to do, beyond describing the tool, can redirect"
        " the assistant's behaviour in every session where the server is installed."),
        ("Keep tool descriptions to what the tool does and what its arguments mean."
        " Remove imperative instructions addressed to the assistant, and anything"
        " asking it to hide behaviour from the user."),
    ),
    "UNICODE-CONCEAL": (
        ("Some characters are invisible to a person reading the code or a description,"
        " but are read by the AI assistant. They can hide text from a human reviewer"
        " while still reaching the model."),
        ("Remove the invisible characters, or replace them with visible equivalents"
        " where they were intended. If the file must contain them, say so in a comment"
        " next to them."),
    ),
    "SCOPE-OVERBROAD": (
        ("A server that listens on every network interface, or accepts requests from"
        " any origin, can be reached by more than the local assistant it was meant to"
        " serve, including other machines on the same network or a web page in the"
        " user's browser."),
        ("Bind to `127.0.0.1` unless remote access is intended, and accept only the"
        " origins you expect."),
    ),
}


@dataclass(frozen=True)
class DraftFinding:
    record: Mapping[str, Any]
    reason: str


@dataclass
class Selection:
    drafts: dict[str, list[DraftFinding]] = field(default_factory=dict)
    already_notified: int = 0
    opted_out: int = 0
    no_longer_produced: int = 0


def select_findings(
    history: Mapping[str, Mapping[str, Any]],
    verified: Mapping[str, str],
    ledger: Sequence[Entry],
) -> Selection:
    """Verified findings still produced, not yet privately reported, by server.

    A contact request does not count as reported: it described nothing, so the
    private notice is still owed.
    """
    reported = {
        finding_id
        for entry in ledger
        if isinstance(entry, Notice) and entry.channel in WINDOW_CHANNELS
        for finding_id in entry.finding_ids
    }
    opted_out = {entry.server_id for entry in ledger if isinstance(entry, OptOut)}
    selection = Selection()
    for finding_id, reason in sorted(verified.items()):
        record = history.get(finding_id)
        if record is None:
            selection.no_longer_produced += 1
        elif finding_id in reported:
            selection.already_notified += 1
        elif record["server_id"] in opted_out:
            selection.opted_out += 1
        else:
            selection.drafts.setdefault(str(record["server_id"]), []).append(
                DraftFinding(record=record, reason=reason)
            )
    return selection


def _permalink(repo_url: str, record: Mapping[str, Any]) -> str:
    location = record["location"]
    return f"{repo_url.rstrip('/')}/blob/{record['commit_sha']}/{location['file']}#L{location['line']}"


def render_notice(
    server_id: str,
    repo_url: str,
    findings: Sequence[DraftFinding],
    channel: ChannelSuggestion | None,
    *,
    now: datetime,
    annotator: str = "<annotator>",
) -> str:
    """One draft notice for one server. Every section is meant to be read and edited."""
    rules = {rule.rule_id: rule for rule in ALL_RULES}
    closes = (now + DISCLOSURE_WINDOW).date().isoformat()
    lines = [
        f"# Private security notice: {server_id}",
        "",
        "DRAFT, not sent. Read every section and rework the marked parts before sending.",
        "",
    ]
    if channel is None:
        lines += ["Channel: not on GitHub; choose one by hand.", ""]
    else:
        lines += [f"Suggested channel: {channel.channel} - {channel.url}", ""]

    lines += ["## What was found", ""]
    for item in findings:
        rule = rules[str(item.record["rule_id"])]
        lines += [
            f"### {rule.title} ({rule.rule_id}, {item.record['severity']})",
            "",
            rule.description,
            "",
            f"- Where: {_permalink(repo_url, item.record)}",
            f"- Commit scanned: `{item.record['commit_sha']}`",
            "",
        ]

    lines += ["## Why it can matter", ""]
    for rule_id in sorted({str(f.record["rule_id"]) for f in findings}):
        lines += [NOTICE_TEXT[rule_id][0], ""]

    lines += ["## Why a person judged it real", ""]
    for item in findings:
        lines += [f"> {REWORK_MARK}", f"> {item.reason or '(no reason recorded)'}", ""]

    lines += ["## Suggested fix", ""]
    for rule_id in sorted({str(f.record["rule_id"]) for f in findings}):
        lines += [NOTICE_TEXT[rule_id][1], ""]

    lines += [
        "## Timeline",
        "",
        ("Nothing about these findings has been published. We will keep them private for"
        f" 90 days from this notice, until {closes} if it is sent today. After that we may"
        " publish the file, the line and the kind of problem, never a working attack."),
        "",
        "## If you disagree, need more time, or want to opt out",
        "",
        ("Reply to this notice to dispute a finding: if it is wrong, it is withdrawn and"
        " never published. If a fix needs more time, ask, and say how much. You can also"
        " opt out of the index entirely; that is honoured without argument."),
        "",
        "## Where this came from",
        "",
        ("These findings come from automated static analysis of your public repository;"
        " your code was read, never installed or run. Each finding was verified by one"
        " person reading the code, who may be wrong."),
        "",
        "---",
        "",
        "After sending, record it (fill in the date sent and the reference):",
        "",
        "```",
        f"mcp-observatory ledger add --server {server_id} "
        + " ".join(f"--finding {f.record['finding_id']}" for f in findings)
        + f" --channel {channel.channel if channel else '<channel>'}"
        + " --notified-at <when sent, e.g. 2026-11-12T10:00:00Z>"
        + " --reference <advisory URL or email>"
        + f" --annotator {annotator}",
        "```",
        "",
    ]
    return "\n".join(lines)


def render_contact_request(server_id: str) -> str:
    """The public issue asking for a contact. It is public, so it describes nothing."""
    return "\n".join(
        [
            "Title: Security contact?",
            "",
            ("Hello. We found something in this repository that we would like to report"
            " privately. Could you tell us how to reach you about a security issue, or"
            " enable GitHub's private vulnerability reporting for this repository? We"
            " will not post any details here."),
            "",
            f"(Repository: {server_id})",
        ]
    )
