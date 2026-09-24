
from analyzer.models import Finding, Location
from evals.golden.sampler import PER_RULE_TARGET, build_entries, stratified_sample


def _finding(rule_id: str, n: int, file: str = "src/index.ts") -> Finding:
    return Finding(
        server_id=f"owner/repo-{n:04d}",
        commit_sha="a" * 40,
        rule_id=rule_id,
        severity="medium",
        confidence="low",
        location=Location(file=file, line=n + 1),
        evidence=f"evidence {n}",
    )


def _population() -> list[Finding]:
    loud = [_finding("SCOPE-OVERBROAD", n) for n in range(500)]
    quiet = [_finding("UNICODE-CONCEAL", n) for n in range(3)]
    return loud + quiet


def test_every_rule_is_represented_however_quiet_it_is() -> None:
    """A uniform draw over this population takes 3 of 503 from the quiet rule
    in expectation, leaving its precision unmeasurable - which is the number
    the whole phase exists to produce.
    """
    sample = stratified_sample(_population(), per_rule=10, seed=7)

    assert {f.rule_id for f in sample} == {"SCOPE-OVERBROAD", "UNICODE-CONCEAL"}


def test_a_rule_with_fewer_findings_than_the_target_contributes_all_of_them() -> None:
    sample = stratified_sample(_population(), per_rule=10, seed=7)

    assert sum(1 for f in sample if f.rule_id == "UNICODE-CONCEAL") == 3
    assert sum(1 for f in sample if f.rule_id == "SCOPE-OVERBROAD") == 10


def test_the_same_seed_draws_the_same_sample() -> None:
    first = stratified_sample(_population(), per_rule=10, seed=7)
    second = stratified_sample(_population(), per_rule=10, seed=7)

    assert [f.finding_id for f in first] == [f.finding_id for f in second]


def test_the_draw_inside_a_rule_is_not_the_first_n_by_server_name() -> None:
    """Taking the first ten would sample by repository name, which correlates
    with anything else alphabetical - publisher, namespace, and the account
    that registered two thousand names in one sitting.
    """
    sample = stratified_sample(_population(), per_rule=10, seed=7)
    lines = sorted(f.location.line for f in sample if f.rule_id == "SCOPE-OVERBROAD")

    assert lines != list(range(1, 11))


def test_a_later_larger_scan_does_not_reshuffle_what_was_already_drawn() -> None:
    """Labels cost hours of a person's time. A draw that moved when the corpus
    grew would throw them away, and nothing would announce it.
    """
    before = stratified_sample(_population(), per_rule=10, seed=7)
    grown = _population() + [_finding("SCOPE-OVERBROAD", n) for n in range(500, 900)]

    after = stratified_sample(
        grown, per_rule=10, seed=7, keep={f.finding_id for f in before}
    )

    assert {f.finding_id for f in before} <= {f.finding_id for f in after}


def test_without_being_told_what_to_keep_a_grown_population_can_move_the_cut() -> None:
    """The reason `keep` exists rather than being left to the hash order. An
    item's position is stable; the sixtieth place is not, so a new finding
    that outranks a drawn one silently replaces it.
    """
    before = stratified_sample(_population(), per_rule=10, seed=7)
    grown = _population() + [_finding("SCOPE-OVERBROAD", n) for n in range(500, 900)]

    after = stratified_sample(grown, per_rule=10, seed=7)

    assert {f.finding_id for f in before} != {f.finding_id for f in after}


def test_the_target_is_the_documented_one() -> None:
    """Spec section 10 targets 200 to 300 overall; sixty across five rules
    lands inside it."""
    assert PER_RULE_TARGET == 60


def test_entries_carry_what_a_labeller_and_a_scorer_both_need() -> None:
    finding = _finding("SHELL-EXEC-UNSAFE", 5, file="src/tools/run.ts")
    entries = build_entries([finding], contexts={finding.finding_id: "a\nb\nc"}, existing=[])

    entry = entries[0]
    assert entry["rule_id"] == "SHELL-EXEC-UNSAFE"
    assert entry["language"] == "typescript"
    assert entry["context"] == "a\nb\nc"
    assert entry["label"] is None
    assert entry["finding_id"] == finding.finding_id


def test_a_finding_with_no_captured_window_is_left_out() -> None:
    """An entry nobody can read is an entry nobody can label, and a blank one
    would be labelled as though the surrounding code were empty.
    """
    kept = _finding("SHELL-EXEC-UNSAFE", 1)
    missing = _finding("SHELL-EXEC-UNSAFE", 2)

    entries = build_entries([kept, missing], contexts={kept.finding_id: "x"}, existing=[])

    assert [e["finding_id"] for e in entries] == [kept.finding_id]


def test_the_flagged_offset_points_at_the_flagged_line_within_the_window() -> None:
    """Twelve when the window is full, less when it was clamped at the top of
    a file. Publishing a fixed twelve would point at the wrong line for every
    finding in the first dozen lines of a file.
    """
    near_top = _finding("SHELL-EXEC-UNSAFE", 2)  # line 3
    middle = _finding("SHELL-EXEC-UNSAFE", 100)  # line 101

    entries = build_entries(
        [near_top, middle],
        contexts={near_top.finding_id: "x", middle.finding_id: "y"},
        existing=[],
    )
    offsets = {e["finding_id"]: e["flagged_offset"] for e in entries}

    assert offsets[near_top.finding_id] == 2
    assert offsets[middle.finding_id] == 12


def test_an_existing_entry_keeps_its_id_and_its_label() -> None:
    """Re-drawing after a later scan must never cost a judgement already made.
    """
    finding = _finding("SHELL-EXEC-UNSAFE", 5)
    existing = [
        {"entry_id": "g-0007", "finding_id": finding.finding_id, "label": "true_positive"}
    ]

    entries = build_entries([finding], contexts={finding.finding_id: "x"}, existing=existing)

    assert entries[0]["entry_id"] == "g-0007"
    assert entries[0]["label"] == "true_positive"


def test_new_entries_are_numbered_after_the_existing_ones() -> None:
    """Ids are append-only, so an id never refers to two different findings
    across two drawings of the set."""
    finding = _finding("SHELL-EXEC-UNSAFE", 5)
    other = _finding("SHELL-EXEC-UNSAFE", 6)
    existing = [{"entry_id": "g-0041", "finding_id": other.finding_id, "label": None}]

    entries = build_entries(
        [finding, other],
        contexts={finding.finding_id: "x", other.finding_id: "y"},
        existing=existing,
    )
    by_finding = {e["finding_id"]: e["entry_id"] for e in entries}

    assert by_finding[other.finding_id] == "g-0041"
    assert by_finding[finding.finding_id] == "g-0042"


def test_a_file_in_an_unknown_language_is_still_labelled() -> None:
    """UNICODE-CONCEAL needs no parser and fires on Markdown and JSON, so a
    sample restricted to parseable files would misrepresent that rule."""
    finding = _finding("UNICODE-CONCEAL", 1, file="docs/readme.md")

    entries = build_entries([finding], contexts={finding.finding_id: "x"}, existing=[])

    assert entries[0]["language"] == "other"


def test_an_existing_entry_whose_finding_is_gone_is_not_resurrected() -> None:
    """A finding the code no longer produces was dropped for a reason; keeping
    its entry would put an unjudgeable row back into the ground truth."""
    finding = _finding("SHELL-EXEC-UNSAFE", 5)
    existing = [{"entry_id": "g-0001", "finding_id": "vanished", "label": "true_positive"}]

    entries = build_entries([finding], contexts={finding.finding_id: "x"}, existing=existing)

    assert [e["finding_id"] for e in entries] == [finding.finding_id]
