from collections.abc import Sequence

import pytest

from evals.harness.stats import (
    brier_score,
    cluster_bootstrap_ci,
    cohens_kappa,
    expected_calibration_error,
    reliability,
    sign_test_sample_size,
)


def test_sample_size_for_a_large_effect() -> None:
    assert sign_test_sample_size(0.75) == 29


def test_sample_size_for_a_small_effect_is_far_larger() -> None:
    assert sign_test_sample_size(0.6) == 194


def test_sample_size_refuses_an_effect_that_is_not_one() -> None:
    with pytest.raises(ValueError):
        sign_test_sample_size(0.5)


def _mean(rows: Sequence[tuple[str, int]]) -> float:
    return sum(v for _, v in rows) / len(rows)


def test_duplicating_rows_inside_a_cluster_does_not_narrow_the_interval() -> None:
    once = [(f"s{n}", n % 2) for n in range(10)]
    tenfold = [row for row in once for _ in range(10)]

    a = cluster_bootstrap_ci(once, cluster=lambda r: r[0], statistic=_mean, seed=7)
    b = cluster_bootstrap_ci(tenfold, cluster=lambda r: r[0], statistic=_mean, seed=7)

    assert a == b


def test_kappa_matches_a_hand_computed_value() -> None:
    first = ["y", "y", "n", "n", "y"]
    second = ["y", "n", "n", "n", "y"]
    assert cohens_kappa(first, second) == pytest.approx(0.6154, abs=1e-4)


def test_kappa_refuses_a_single_category() -> None:
    with pytest.raises(ValueError):
        cohens_kappa(["y", "y"], ["y", "y"])


def test_a_perfect_prediction_has_zero_brier() -> None:
    assert brier_score([1.0, 0.0], [True, False]) == 0.0


def test_a_calibrated_predictor_has_zero_calibration_error() -> None:
    probabilities = [0.8] * 10 + [0.2] * 10
    outcomes = [True] * 8 + [False] * 2 + [True] * 2 + [False] * 8
    assert expected_calibration_error(reliability(probabilities, outcomes)) == pytest.approx(0.0)


def test_an_overconfident_predictor_is_caught() -> None:
    probabilities = [0.9] * 10
    outcomes = [True] * 5 + [False] * 5
    assert expected_calibration_error(reliability(probabilities, outcomes)) == pytest.approx(0.4)


def test_the_sign_test_is_one_for_no_evidence_and_small_for_a_lopsided_split() -> None:
    from evals.harness.stats import sign_test
    assert sign_test(0, 0) == 1.0
    assert sign_test(16, 1) < 0.001
