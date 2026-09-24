"""The baseline: publish what the rules said, and call all of it real."""

from collections.abc import Mapping
from typing import Any

from analyzer.triage.base import Decision


class RulesOnlyAdjudicator:
    """What publishing untriaged rule output actually claims.

    Recall is 1.0 by construction and precision is the corpus base rate. That
    is the number the paid arms have to beat to justify costing anything, and
    if neither does, the publishable answer is deterministic rules only -
    which spec section 14 already names as the fallback rather than a defeat.

    Mapping the rule's own `confidence` to invented probabilities was
    considered and rejected. Those numbers would be three values nobody
    measured, and the comparison would quietly become a test of them rather
    than of the adjudicators.
    """

    name = "rules-only"

    def decide(self, entry: Mapping[str, Any]) -> Decision:
        return Decision(probability=1.0, cost_usd=0.0, latency_ms=0.0)
