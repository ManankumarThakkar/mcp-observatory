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


class Adjudicator(Protocol):
    """Anything that can judge a finding.

    Structural, so a candidate needs no base class and imports nothing from
    here. The deferred register asks that a further arm be swappable without
    rework, and a nominal base class is precisely what would make that a
    rewrite instead.
    """

    name: str

    def decide(self, entry: Mapping[str, Any]) -> Decision: ...
