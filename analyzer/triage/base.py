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


def present(entry: Mapping[str, Any]) -> str:
    """The window with the flagged line marked.

    The marker is not decoration. The window is twenty-five lines and the
    flagged line is not reliably the middle one, because the capture clamps
    near the top of a file. Without the mark, the reader - human or model - is
    being asked which of twenty-five lines is the question.
    """
    offset = int(entry["flagged_offset"])
    return "\n".join(
        f"{FLAGGED_MARKER if index == offset else QUIET_MARKER}{line}"
        for index, line in enumerate(str(entry["context"]).splitlines())
    )


class Adjudicator(Protocol):
    """Anything that can judge a finding.

    Structural, so a candidate needs no base class and imports nothing from
    here. The deferred register asks that a further arm be swappable without
    rework, and a nominal base class is precisely what would make that a
    rewrite instead.
    """

    name: str

    def decide(self, entry: Mapping[str, Any]) -> Decision: ...
