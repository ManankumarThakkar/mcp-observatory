"""What every adjudicator returns, whatever it is underneath."""

import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class Decision:
    """One adjudication, with what it cost to make.

    A probability rather than a verdict, per `DECISIONS.md` D12: a number that
    means what it says can be thresholded, tuned and published as precision
    and recall *at that threshold*, so a reader can see the trade we chose and
    disagree with it. A free-text verdict carries no confidence anyone can
    inspect, and everything downstream ends up parsing prose to recover a
    judgement the model never expressed.

    Cost and latency are fields rather than an afterthought, because the
    benchmark publishes cost per decision per rule. A figure reconstructed
    afterwards from a price list is an estimate wearing a measurement's
    clothes, which is the failure this project refuses about accuracy and
    should equally refuse about cost.
    """

    probability: float
    cost_usd: float
    latency_ms: float

    def __post_init__(self) -> None:
        # Validated at construction, like Finding's severity. A threshold is
        # applied to this number and published beside the result, so a value
        # outside the range makes the published threshold describe something
        # other than what was measured, while looking entirely ordinary
        # everywhere downstream.
        #
        # NaN is checked explicitly because every comparison against it is
        # False, so a range check alone accepts it and it then poisons any
        # average it reaches.
        if math.isnan(self.probability) or not 0.0 <= self.probability <= 1.0:
            raise ValueError(f"probability must be in [0, 1], got {self.probability}")
        if self.cost_usd < 0:
            raise ValueError(f"cost must not be negative, got {self.cost_usd}")


# How a window is shown, to a human labeller and to every adjudicator alike.
# One definition, because the benchmark's entire claim is that it compares
# judgement: if the labeller saw the flagged line marked and a model did not,
# the difference reported would be a difference in presentation.
FLAGGED_MARKER = "> "
QUIET_MARKER = "  "
TRUNCATION_MARKER = " ...[truncated]"

# The capture bounds the window in lines, and a line is unbounded. Measured on
# the real golden set: one UNICODE-CONCEAL window was 176,331 characters,
# because the finding sat inside a one-line JSON export, and a
# TOOL-DESC-INJECTION one was 62,635. That is unreadable to a labeller, costs
# tokens nobody agreed to, and was rejected outright by the decision service.
#
# Bounded here rather than at capture, because this is the single place both
# the human and every model are shown the window: capping it here makes them
# equal by construction, and needs no redraw of a set already labelled.
MAX_LINE_CHARS = 200
MAX_WINDOW_CHARS = 8_000


def _clip(line: str) -> str:
    """One line, bounded. The start is kept, because that is where the code is."""
    if len(line) <= MAX_LINE_CHARS:
        return line
    return line[:MAX_LINE_CHARS] + TRUNCATION_MARKER


def present(entry: Mapping[str, Any]) -> str:
    """The window with the flagged line marked, bounded in size.

    The marker is not decoration. The window is twenty-five lines and the
    flagged line is not reliably the middle one, because the capture clamps
    near the top of a file. Without the mark, the reader - human or model - is
    being asked which of twenty-five lines is the question.

    Lines are clipped individually and then the whole window is capped. The
    window-level cap grows outward from the flagged line rather than cutting
    from the end, because a cut that removed the thing being asked about would
    leave a question with no subject and nothing would say so.
    """
    offset = int(entry["flagged_offset"])
    lines = [
        f"{FLAGGED_MARKER if index == offset else QUIET_MARKER}{_clip(line)}"
        for index, line in enumerate(str(entry["context"]).splitlines())
    ]
    if not lines:
        return ""

    # Grow outward from the flagged line, so it always survives. Indices
    # rather than line text: a window legitimately contains repeated lines - a
    # blank one, a lone closing brace - and collecting text into a set would
    # silently collapse them and misalign everything a reader counts.
    centre = min(offset, len(lines) - 1)
    kept = [centre]
    size = len(lines[centre])
    before, after = centre - 1, centre + 1

    while True:
        added = False
        for index in (before, after):
            if 0 <= index < len(lines) and size + len(lines[index]) + 1 <= MAX_WINDOW_CHARS:
                size += len(lines[index]) + 1
                kept.append(index)
                added = True
        if not added:
            break
        before -= 1
        after += 1

    return "\n".join(lines[index] for index in sorted(kept))


class Adjudicator(Protocol):
    """Anything that can judge a finding.

    Structural, so a candidate needs no base class and imports nothing from
    here. The deferred register asks that a further arm be swappable without
    rework, and a nominal base class is precisely what would make that a
    rewrite instead.
    """

    name: str

    def decide(self, entry: Mapping[str, Any]) -> Decision: ...
