"""Record one human judgement per finding, from the window the models see."""

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from analyzer.rules import ALL_RULES
from analyzer.triage.base import present

# `unsure` is deliberately available. A finding that cannot be decided from
# the captured window is a fact about the window, and forcing it into one of
# the two real buckets puts noise into the ground truth that every adjudicator
# is then scored against. Unsure entries are excluded from precision and
# recall and their count is published: a large share means twelve lines either
# side is too narrow, and that is a measurement rather than an inconvenience.
LABELS: tuple[str, ...] = ("true_positive", "false_positive", "unsure")

# Who made a judgement. A mixed set is the intended end state - a model labels
# the whole corpus, a person validates a random subset - and without provenance
# the two become indistinguishable the moment they are written to one file.
# A closed set rather than free text, because provenance nobody can filter on
# is not provenance.
LABELLERS: tuple[str, ...] = ("human", "model")

# What the labeller presses. Single keystrokes because there are three hundred
# of them, and `b` because there will be slips.
KEYS: Mapping[str, str] = {"y": "true_positive", "n": "false_positive", "u": "unsure"}

def next_unlabelled(entries: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """The first entry still waiting for a judgement, or None if there is none."""
    return next((entry for entry in entries if entry.get("label") is None), None)


def last_labelled(entries: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """The most recent judgement, so it can be taken back.

    Three hundred single-keystroke decisions will contain a slip. Without
    undo the only remedy is hand-editing the data file, which is how a ground
    truth acquires an error that nothing can see and everything is scored
    against.
    """
    labelled = [entry for entry in entries if entry.get("label") is not None]
    return labelled[-1] if labelled else None


def progress(entries: Sequence[Mapping[str, Any]]) -> tuple[int, int]:
    """How many are judged, and how many there are. Work without a visible end
    is work somebody abandons."""
    return sum(1 for entry in entries if entry.get("label") is not None), len(entries)


def apply_label(
    entries: Sequence[Mapping[str, Any]],
    entry_id: str,
    label: str | None,
    *,
    reason: str = "",
    by: str = "human",
) -> list[dict[str, Any]]:
    """Return the entries with one judgement recorded, or taken back.

    A model must give a reason; a person need not. The asymmetry is deliberate.
    A person pressing one key has already spent the attention that makes the
    judgement worth something, while a model can produce a confident answer for
    free - so the cost of an unexamined one is reimposed by requiring it to
    write down why. It also makes the label auditable: a reader can disagree
    with one entry rather than with the corpus.

    Refuses an unknown label rather than storing it. A typo would enter the
    ground truth silently and then be scored as a disagreement against all
    three adjudicators, making every one of them look worse for a reason that
    has nothing to do with any of them.

    Refuses an unknown entry for the same class of reason: doing nothing looks
    exactly like success, and the entry would simply be asked again.
    """
    if label is not None and label not in LABELS:
        raise ValueError(f"label must be one of {', '.join(LABELS)}, got {label!r}")
    if by not in LABELLERS:
        raise ValueError(f"labeller must be one of {', '.join(LABELLERS)}, got {by!r}")
    if label is not None and by == "model" and not reason.strip():
        raise ValueError("a model label needs a reason, so the judgement can be audited")
    if not any(entry["entry_id"] == entry_id for entry in entries):
        raise KeyError(f"no entry {entry_id}")

    def relabel(entry: Mapping[str, Any]) -> dict[str, Any]:
        if label is None:
            return {**entry, "label": None, "reason": "", "labelled_by": None}
        return {**entry, "label": label, "reason": reason, "labelled_by": by}

    return [
        relabel(entry) if entry["entry_id"] == entry_id else dict(entry)
        for entry in entries
    ]


def render(entry: Mapping[str, Any], rules: Mapping[str, tuple[str, str]]) -> str:
    """The view a labeller judges from, and nothing else.

    What is shown: the claim the rule makes, the language, and the window with
    the flagged line marked. The claim is the question being asked, not an
    anchor - without it the labeller is guessing what they are being asked.

    What is withheld, and why each one matters. The severity and the rule's
    own confidence say the scanner already believes this, which anchors the
    answer to the thing being judged. The server name invites reputation to
    decide it: a well-known publisher makes a finding feel like a false
    positive and an unknown one makes it feel real, and neither is evidence.
    The file path is withheld for the same reason the published entry omits
    it, so the labeller judges exactly what a reader of the benchmark will.

    The flagged line is marked because twenty-five lines with nothing marked
    asks the labeller to guess the question, and it is not reliably the middle
    line: the window clamps near the top of a file.
    """
    title, description = rules[entry["rule_id"]]
    return "\n".join(
        [
            f"[{entry['entry_id']}]  {entry['rule_id']}  ({entry['language']})",
            "",
            f"  Claim: {title}",
            f"  {description}",
            "",
            # Shared with the adjudicators rather than duplicated, so the
            # human and the models are shown the same window by construction.
            present(entry),
        ]
    )


def rule_text() -> dict[str, tuple[str, str]]:
    """Each rule's published title and description, keyed by rule id.

    Taken from the rules themselves rather than restated, so the question put
    to a labeller is the same claim the published finding makes. Two copies
    would drift, and the drift would be invisible: the benchmark would report
    a precision for a question nobody was asking any more.
    """
    return {rule.rule_id: (rule.title, rule.description) for rule in ALL_RULES}


def _write(path: Path, entries: Sequence[Mapping[str, Any]]) -> None:
    """Write after every judgement, never at exit.

    A session interrupted by a closed laptop must not lose an hour of work,
    and three hundred judgements will be interrupted.
    """
    path.write_text(
        "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in entries),
        encoding="utf-8",
    )


def run(path: Path) -> int:
    """Label until the set is done or the labeller stops."""
    entries: list[dict[str, Any]] = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    rules = rule_text()

    while True:
        done, total = progress(entries)
        entry = next_unlabelled(entries)
        if entry is None:
            print(f"\nAll {total} entries labelled.", file=sys.stderr)
            return 0

        print("\n" + "=" * 72)
        print(f"{done}/{total} labelled")
        print(render(entry, rules))
        answer = input("\n[y] real  [n] not real  [u] unsure  [b] undo  [q] save and quit > ").strip().lower()

        if answer == "q":
            print(f"Saved. {done} of {total} labelled.", file=sys.stderr)
            return 0
        if answer == "b":
            previous = last_labelled(entries)
            if previous is not None:
                entries = apply_label(entries, str(previous["entry_id"]), None)
                _write(path, entries)
            continue
        if answer in KEYS:
            entries = apply_label(entries, str(entry["entry_id"]), KEYS[answer])
            _write(path, entries)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    parser.add_argument(
        "--path",
        type=Path,
        default=Path(".cache/golden-entries.jsonl"),
        help="The entries file to label. Written after every keystroke.",
    )
    args = parser.parse_args(argv)
    if not args.path.exists():
        raise FileNotFoundError(f"no entries at {args.path}; draw the golden set first")
    return run(args.path)


if __name__ == "__main__":
    raise SystemExit(main())
