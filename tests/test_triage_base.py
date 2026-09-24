import pytest

from analyzer.triage.base import Adjudicator, Decision
from analyzer.triage.rules_only import RulesOnlyAdjudicator

ENTRY = {
    "entry_id": "g-0001",
    "rule_id": "SCOPE-OVERBROAD",
    "language": "typescript",
    "context": "app.listen(3000, '0.0.0.0')",
    "flagged_offset": 0,
}


def test_the_baseline_calls_every_finding_real() -> None:
    """Publishing untriaged rule output asserts exactly this. It is the claim
    the paid arms have to beat to justify costing anything."""
    assert RulesOnlyAdjudicator().decide(ENTRY).probability == 1.0


def test_the_baseline_costs_nothing_and_that_is_the_point() -> None:
    """Cost per decision is one of the three published figures, and a local
    arm's zero is what the others are measured against."""
    assert RulesOnlyAdjudicator().decide(ENTRY).cost_usd == 0.0


def test_the_baseline_satisfies_the_protocol_structurally() -> None:
    """Structural, so a fourth candidate needs no base class and imports
    nothing from here. A nominal base class is the thing that would turn
    swapping an arm into a rewrite."""
    adjudicator: Adjudicator = RulesOnlyAdjudicator()

    assert adjudicator.name == "rules-only"


@pytest.mark.parametrize("probability", [-0.1, 1.1, float("nan")])
def test_a_probability_outside_zero_to_one_is_refused(probability: float) -> None:
    """A threshold is applied to this number and published beside the result.
    A value outside the range makes the published threshold describe something
    other than what was measured, and says so nowhere downstream."""
    with pytest.raises(ValueError, match="probability"):
        Decision(probability=probability, cost_usd=0.0, latency_ms=1.0)


def test_a_negative_cost_is_refused() -> None:
    """Costs are summed into a published per-decision figure, where one
    negative entry silently subtracts from the total."""
    with pytest.raises(ValueError, match="cost"):
        Decision(probability=0.5, cost_usd=-0.01, latency_ms=1.0)


def test_the_boundaries_of_the_range_are_allowed() -> None:
    """Certainty in either direction is a legitimate answer, and an
    off-by-one here would reject exactly the baseline arm."""
    assert Decision(probability=0.0, cost_usd=0.0, latency_ms=0.0).probability == 0.0
    assert Decision(probability=1.0, cost_usd=0.0, latency_ms=0.0).probability == 1.0
