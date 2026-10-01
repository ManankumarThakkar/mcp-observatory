import json
import random
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from analyzer.sampling import draw
from evals.golden.study import (
    CONTROL_SIZE,
    STUDY_SEED,
    annotation_sample,
    probability_digest,
    snapshot_digest,
)
from evals.harness.analysis import (
    credulous_share,
    credulous_share_ci,
    h1_lines,
    h2_lines,
    h3_lines,
    h4_lines,
    load_study,
    main,
    one_per_server,
    read_adjudications,
    study_lines,
    unsure_line,
    window_errors,
)


def _e(
    i: int,
    window: float,
    function: float,
    label: str | None,
    *,
    by: str = "human",
    server: str = "s/a",
) -> dict[str, Any]:
    return {
        "entry_id": f"g-{i}",
        "server_id": server,
        "label": label,
        "labelled_by": by if label is not None else None,
        "probabilities": {"window": window, "function": function},
    }


# H1


def test_only_human_labels_count() -> None:
    rows = window_errors(
        [_e(1, 0.8, 0.2, "false_positive", by="model"), _e(2, 0.8, 0.2, "false_positive")]
    )
    assert [r.entry_id for r in rows] == ["g-2"]


def test_only_disagreements_the_window_got_wrong_count() -> None:
    entries = [
        _e(1, 0.8, 0.2, "false_positive"),  # window wrong, credulous
        _e(2, 0.2, 0.8, "true_positive"),  # window wrong, missed
        _e(3, 0.8, 0.2, "true_positive"),  # window right
        _e(4, 0.8, 0.8, "false_positive"),  # no disagreement
        _e(5, 0.8, 0.2, "unsure"),  # excluded
    ]
    rows = window_errors(entries)
    assert [r.credulous for r in rows] == [True, False]
    assert credulous_share(rows) == 0.5


def test_one_server_cannot_dominate_the_interval() -> None:
    heavy = [_e(i, 0.8, 0.2, "false_positive", server="s/big") for i in range(20)]
    light = [_e(100 + i, 0.2, 0.8, "true_positive", server=f"s/{i}") for i in range(4)]
    rows = window_errors(heavy + light)
    low, high = credulous_share_ci(rows, seed=3)
    assert low < 0.5 < high, "twenty findings from one server were treated as twenty servers"
    assert len(one_per_server(rows, seed=3)) == 5


def test_one_per_server_does_not_depend_on_the_order_findings_arrive_in() -> None:
    # Keeping the "first" error per server would let file order choose the
    # result, which a reader could not tell from a choice made to suit it.
    entries = [
        _e(i, 0.8, 0.2, "false_positive", server=f"s/{i % 3}") for i in range(6)
    ] + [_e(10 + i, 0.2, 0.8, "true_positive", server=f"s/{i % 3}") for i in range(6)]
    kept = {r.entry_id for r in one_per_server(window_errors(entries), seed=5)}
    shuffled = entries[:]
    random.Random(1).shuffle(shuffled)
    assert {r.entry_id for r in one_per_server(window_errors(shuffled), seed=5)} == kept


def test_one_per_server_keeps_the_hashed_draw_the_registration_names() -> None:
    entries = [_e(i, 0.8, 0.2, "false_positive", server="s/1") for i in range(8)]
    rows = window_errors(entries)
    expected = draw(rows, 1, seed=STUDY_SEED, key=lambda r: (r.entry_id,))[0]
    assert one_per_server(rows, seed=STUDY_SEED) == [expected]


def test_h1_says_so_when_there_is_nothing_to_test() -> None:
    assert h1_lines([_e(1, 0.8, 0.2, "false_positive", by="model")], seed=1) == [
        "H1: no human-labelled window errors, so nothing to test."
    ]


def test_h1_reports_counts_interval_and_the_one_per_server_check() -> None:
    entries = [_e(i, 0.8, 0.2, "false_positive", server=f"s/{i}") for i in range(12)]
    lines = h1_lines(entries, seed=1)
    assert "12 credulous, 0 missed" in lines[0]
    assert "sign test p = 0.0005" in lines[0]
    assert "server-clustered interval" in lines[1]
    assert "one finding per server: 12 credulous of 12" in lines[2]


# H2


def test_h2_counts_flips_over_paired_findings() -> None:
    entries = [
        _e(1, 0.8, 0.2, None, server="s/1"),
        _e(2, 0.8, 0.8, None, server="s/2"),
        {"entry_id": "g-3", "server_id": "s/3", "probabilities": {"window": 0.8}},
    ]
    assert "1 of 2 paired findings (50.0%)" in h2_lines(entries, seed=1)[0]


def test_h2_also_reports_the_estimate_without_the_largest_server() -> None:
    entries = [_e(i, 0.8, 0.2, None, server="s/big") for i in range(3)] + [
        _e(10, 0.8, 0.2, None, server="s/1"),
        _e(11, 0.8, 0.8, None, server="s/2"),
        _e(12, 0.8, 0.8, None, server="s/3"),
    ]
    sensitivity = h2_lines(entries, seed=1)[1]
    assert "without s/big (3 of 4 flips)" in sensitivity
    assert "1 of 3 paired findings (33.3%)" in sensitivity


# H3


def test_h3_reports_which_view_people_sided_with_and_claims_nothing() -> None:
    entries = [
        _e(1, 0.8, 0.2, "false_positive"),  # function right
        _e(2, 0.8, 0.2, "false_positive"),  # function right
        _e(3, 0.2, 0.8, "false_positive"),  # window right
        _e(4, 0.8, 0.2, "unsure"),  # excluded
        _e(5, 0.8, 0.8, "true_positive"),  # agreement, not counted
    ]
    lines = h3_lines(entries)
    assert "function right 2, window right 1, of 3 decided disagreements" in lines[0]
    assert all("p =" not in line for line in lines), "H3 is registered as descriptive only"


# H4


def test_h4_measures_calibration_on_the_control_only() -> None:
    inside = [_e(i, 0.9, 0.9, "true_positive", server=f"s/{i}") for i in range(4)]
    outside = [_e(10, 0.9, 0.9, "false_positive", server="s/x")]
    lines = h4_lines(inside + outside, frozenset(e["entry_id"] for e in inside))
    window = next(line for line in lines if line.startswith("H4 window"))
    assert window.startswith("H4 window: n=4")


def test_h4_prints_the_reliability_table_it_registered() -> None:
    control = [_e(i, 0.1 + 0.2 * (i % 5), 0.5, "true_positive", server=f"s/{i}") for i in range(10)]
    lines = h4_lines(control, frozenset(e["entry_id"] for e in control))
    assert any(line.strip().startswith("0.00-0.20") for line in lines)


def test_h4_reports_the_model_against_people() -> None:
    entries = [
        {**_e(1, 0.8, 0.2, "true_positive"), "model_label": "true_positive"},
        {**_e(2, 0.8, 0.2, "false_positive"), "model_label": "true_positive"},
    ]
    assert "1/2 agree" in h4_lines(entries, frozenset())[-1]


# Exclusions and order


def test_unsure_answers_are_counted_not_silently_dropped() -> None:
    entries = [
        _e(1, 0.8, 0.2, "unsure"),
        _e(2, 0.8, 0.2, "unsure", by="model"),
        _e(3, 0.8, 0.2, "true_positive"),
    ]
    assert unsure_line(entries) == (
        "Unsure: 1 of 2 human-labelled findings, 1 of them on a disagreement; "
        "excluded from H1 and H3."
    )


def test_the_study_prints_every_registered_hypothesis_in_order() -> None:
    entries = [_e(i, 0.8, 0.2, "false_positive", server=f"s/{i}") for i in range(3)]
    lines = study_lines(entries, {"sample_seed": 1, "control": ["g-0"]})
    first = [
        next(i for i, line in enumerate(lines) if line.startswith(tag))
        for tag in ("Unsure", "H1", "H2", "H3", "H4")
    ]
    assert first == sorted(first), "hypotheses must print in registration order"


# Loading the frozen study


def _manifest(entries: list[dict[str, Any]]) -> dict[str, Any]:
    sample = annotation_sample(entries, control_size=CONTROL_SIZE, seed=STUDY_SEED)
    return {
        "digest": snapshot_digest(entries),
        "probability_digest": probability_digest(entries),
        "queue": sample.queue,
        "disagreement": sorted(sample.disagreement),
        "control": sorted(sample.control),
        "sample_seed": STUDY_SEED,
    }


def _frozen(
    tmp_path: Path, entries: list[dict[str, Any]], **overrides: Any
) -> tuple[Path, Path]:
    snapshot, manifest = tmp_path / "snapshot.jsonl", tmp_path / "manifest.json"
    snapshot.write_text("".join(json.dumps(e) + "\n" for e in entries))
    manifest.write_text(json.dumps({**_manifest(entries), **overrides}))
    return snapshot, manifest


def _unpaired(i: int) -> dict[str, Any]:
    return {"entry_id": f"g-{i}", "server_id": "s/a", "probabilities": {"window": 0.8}}


def _votes(**labels: str) -> dict[str, dict[str, Any]]:
    return {entry_id.replace("_", "-"): {"label": label} for entry_id, label in labels.items()}


def test_a_changed_snapshot_is_refused_before_any_label_is_read(tmp_path: Path) -> None:
    snapshot, manifest = _frozen(tmp_path, [_e(1, 0.8, 0.2, None)])
    snapshot.write_text(json.dumps({**_e(1, 0.8, 0.2, None), "context": "edited"}) + "\n")
    with pytest.raises(RuntimeError, match="changed after freezing"):
        load_study(snapshot, manifest, {"manan": _votes(g_1="true_positive")})


def test_the_analysis_refuses_to_run_before_annotation_is_complete(tmp_path: Path) -> None:
    # The registration fixes that no analysis runs until annotation is complete.
    # Enforced here so a partial result cannot be looked at, not just discouraged.
    snapshot, manifest = _frozen(tmp_path, [_e(1, 0.8, 0.2, None), _e(2, 0.8, 0.2, None)])
    with pytest.raises(RuntimeError, match="1 of 2 queued findings have no label"):
        load_study(snapshot, manifest, {"manan": _votes(g_1="true_positive")})


def test_a_label_for_a_finding_outside_the_queue_is_refused(tmp_path: Path) -> None:
    snapshot, manifest = _frozen(tmp_path, [_e(1, 0.8, 0.2, None), _unpaired(2)])
    with pytest.raises(RuntimeError, match="outside the registered queue"):
        load_study(
            snapshot, manifest, {"manan": _votes(g_1="true_positive", g_2="true_positive")}
        )


def test_an_unresolved_disagreement_between_annotators_is_refused(tmp_path: Path) -> None:
    # Dropping the findings two people disagree on would remove the hardest
    # cases from H1 and bias it; they must be adjudicated first.
    snapshot, manifest = _frozen(tmp_path, [_e(1, 0.8, 0.2, None)])
    annotations = {"manan": _votes(g_1="true_positive"), "second": _votes(g_1="false_positive")}
    with pytest.raises(RuntimeError, match="1 finding the annotators disagree on"):
        load_study(snapshot, manifest, annotations)


def test_people_s_labels_replace_the_model_s_and_keep_it_for_comparison(tmp_path: Path) -> None:
    entry = {**_e(1, 0.8, 0.2, "true_positive", by="model"), "reason": "reaches the sink"}
    snapshot, manifest = _frozen(tmp_path, [entry])
    entries, _ = load_study(snapshot, manifest, {"manan": _votes(g_1="false_positive")})
    assert entries[0]["label"] == "false_positive"
    assert entries[0]["labelled_by"] == "human"
    assert entries[0]["model_label"] == "true_positive"


def test_the_command_reads_the_annotator_s_file_and_prints_the_study(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    snapshot, manifest = _frozen(tmp_path, [_e(1, 0.8, 0.2, None)])
    annotations = tmp_path / ".cache" / "annotations" / "manan.jsonl"
    annotations.parent.mkdir(parents=True)
    annotations.write_text(json.dumps({"entry_id": "g-1", "label": "false_positive"}) + "\n")
    assert main(["--snapshot", str(snapshot), "--manifest", str(manifest), "--annotator", "manan"]) == 0
    assert "H1: window errors on disagreements" in capsys.readouterr().out


def test_the_analysis_cannot_reach_a_judge() -> None:
    # The registration says no judge is called again. Importing nothing that
    # can call one makes that structural, not a matter of a warm cache.
    probe = (
        "import sys, evals.harness.analysis\n"
        "reachable = [m for m in ('analyzer.triage.jev', 'analyzer.triage.frontier',"
        " 'analyzer.triage.cache', 'urllib.request') if m in sys.modules]\n"
        "print(reachable)"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]"



def test_a_finding_without_a_server_is_refused_not_merged_into_one_cluster() -> None:
    entry = _e(1, 0.8, 0.2, "false_positive")
    del entry["server_id"]
    with pytest.raises(KeyError):
        window_errors([entry])


def test_a_rewritten_judge_answer_is_refused(tmp_path: Path) -> None:
    # The snapshot digest leaves probabilities out by design, so a re-run judge
    # writing new answers would otherwise pass unnoticed.
    snapshot, manifest = _frozen(tmp_path, [_e(1, 0.8, 0.2, None)])
    snapshot.write_text(json.dumps(_e(1, 0.8, 0.21, None)) + "\n")
    with pytest.raises(RuntimeError, match="judges' stored answers changed"):
        load_study(snapshot, manifest, {"manan": _votes(g_1="true_positive")})


def test_a_manifest_on_another_seed_is_refused(tmp_path: Path) -> None:
    snapshot, manifest = _frozen(tmp_path, [_e(1, 0.8, 0.2, None)], sample_seed=20260923)
    with pytest.raises(RuntimeError, match="not the registered seed"):
        load_study(snapshot, manifest, {"manan": _votes(g_1="true_positive")})


def test_a_queue_that_does_not_follow_from_the_snapshot_is_refused(tmp_path: Path) -> None:
    entries = [_e(1, 0.8, 0.2, None), _e(2, 0.8, 0.8, None)]
    snapshot, manifest = _frozen(tmp_path, entries, queue=["g-1"], control=[])
    with pytest.raises(RuntimeError, match="does not follow from the snapshot"):
        load_study(snapshot, manifest, {"manan": _votes(g_1="true_positive")})


def test_a_snapshot_already_carrying_a_human_label_is_refused(tmp_path: Path) -> None:
    # Labels live in the annotators' own files; the frozen snapshot never holds one.
    snapshot, manifest = _frozen(tmp_path, [_e(1, 0.8, 0.2, "true_positive")])
    with pytest.raises(RuntimeError, match="already carries a human label"):
        load_study(snapshot, manifest, {"manan": _votes(g_1="true_positive")})


def test_an_adjudication_settles_a_disagreement(tmp_path: Path) -> None:
    snapshot, manifest = _frozen(tmp_path, [_e(1, 0.8, 0.2, None)])
    annotations = {"manan": _votes(g_1="true_positive"), "second": _votes(g_1="false_positive")}
    entries, _ = load_study(snapshot, manifest, annotations, adjudicated={"g-1": "false_positive"})
    assert entries[0]["label"] == "false_positive"


def test_an_adjudication_of_a_finding_nobody_disputed_is_refused(tmp_path: Path) -> None:
    snapshot, manifest = _frozen(tmp_path, [_e(1, 0.8, 0.2, None)])
    with pytest.raises(RuntimeError, match="not in dispute"):
        load_study(
            snapshot,
            manifest,
            {"manan": _votes(g_1="true_positive")},
            adjudicated={"g-1": "false_positive"},
        )


def test_every_adjudication_carries_its_reason(tmp_path: Path) -> None:
    path = tmp_path / "adjudicated.jsonl"
    path.write_text(json.dumps({"entry_id": "g-1", "label": "false_positive", "reason": ""}) + "\n")
    with pytest.raises(ValueError, match="needs a reason"):
        read_adjudications(path)
    path.write_text(
        json.dumps({"entry_id": "g-1", "label": "false_positive", "reason": "guarded upstream"})
        + "\n"
    )
    assert read_adjudications(path) == {"g-1": "false_positive"}


def test_a_missing_annotator_file_is_refused_not_read_as_no_votes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A misspelt second annotator would otherwise vanish, and with them every
    # disagreement they would have raised.
    monkeypatch.chdir(tmp_path)
    snapshot, manifest = _frozen(tmp_path, [_e(1, 0.8, 0.2, None)])
    annotations = tmp_path / ".cache" / "annotations" / "manan.jsonl"
    annotations.parent.mkdir(parents=True)
    annotations.write_text(json.dumps({"entry_id": "g-1", "label": "false_positive"}) + "\n")
    argv = ["--snapshot", str(snapshot), "--manifest", str(manifest)]
    with pytest.raises(FileNotFoundError, match="secnod"):
        main([*argv, "--annotator", "manan", "--annotator", "secnod"])
