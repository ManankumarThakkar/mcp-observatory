import json
from pathlib import Path
from typing import Any

import pytest

from evals.golden.label import (
    LABELS,
    apply_label,
    is_contested,
    last_labelled,
    next_unlabelled,
    observe,
    progress,
    published_label,
    record_truth,
    render,
)

ENTRIES: list[dict[str, Any]] = [
    {"entry_id": "g-0001", "rule_id": "SHELL-EXEC-UNSAFE", "label": "true_positive"},
    {"entry_id": "g-0002", "rule_id": "SCOPE-OVERBROAD", "label": None},
    {"entry_id": "g-0003", "rule_id": "SCOPE-OVERBROAD", "label": None},
]


def test_labelling_resumes_where_it_stopped() -> None:
    """Three hundred judgements is several sittings. A tool that restarts from
    the top re-asks questions already answered and wastes the scarcest input
    this project has.
    """
    entry = next_unlabelled(ENTRIES)

    assert entry is not None
    assert entry["entry_id"] == "g-0002"


def test_a_fully_labelled_set_has_nothing_left_to_ask() -> None:
    assert next_unlabelled([{**e, "label": "false_positive"} for e in ENTRIES]) is None


def test_applying_a_label_leaves_every_other_entry_alone() -> None:
    updated = apply_label(ENTRIES, "g-0002", "false_positive", by="human")

    assert updated[1]["label"] == "false_positive"
    assert updated[0]["label"] == "true_positive"
    assert updated[2]["label"] is None


def test_an_unknown_label_is_refused() -> None:
    """A typo would enter the ground truth silently and then be scored as a
    disagreement against all three adjudicators, making every one of them look
    worse for a reason that has nothing to do with any of them.
    """
    with pytest.raises(ValueError, match="label"):
        apply_label(ENTRIES, "g-0002", "probably", by="human")


def test_unsure_is_a_first_class_answer() -> None:
    """A finding nobody can decide from the window is a fact about the window.
    Forcing it into one of the two real buckets puts noise into the ground
    truth, and every arm is then scored against a coin flip.
    """
    assert "unsure" in LABELS
    assert apply_label(ENTRIES, "g-0002", "unsure", by="human")[1]["label"] == "unsure"


def test_labelling_an_entry_that_does_not_exist_is_refused() -> None:
    """Silently doing nothing looks identical to success, and the entry would
    simply be asked again next session."""
    with pytest.raises(KeyError, match="g-9999"):
        apply_label(ENTRIES, "g-9999", "true_positive", by="human")


def test_the_last_judgement_can_be_found_again_to_undo_it() -> None:
    """Three hundred single-keystroke decisions will contain a slip, and
    without undo the only remedy is editing the data file by hand, which is
    how a ground truth acquires an error nobody can see.
    """
    entry = last_labelled(ENTRIES)

    assert entry is not None
    assert entry["entry_id"] == "g-0001"


def test_undo_has_nothing_to_do_on_an_untouched_set() -> None:
    assert last_labelled([{**e, "label": None} for e in ENTRIES]) is None


def test_progress_counts_what_is_done_against_the_whole() -> None:
    """Labelling without a visible end is labelling somebody abandons."""
    assert progress(ENTRIES) == (1, 3)


RULES = {"SHELL-EXEC-UNSAFE": ("Shell built from tool input", "A shell command is built from a string.")}

ENTRY: dict[str, Any] = {
    "entry_id": "g-0001",
    "rule_id": "SHELL-EXEC-UNSAFE",
    "severity": "critical",
    "confidence": "low",
    "server_id": "acme/notes-server",
    "file": "src/tools/run.ts",
    "language": "typescript",
    "context": "const a = 1\nexec(cmd)\nconst b = 2",
    "flagged_offset": 1,
    "label": None,
}


def test_the_view_states_the_claim_being_judged() -> None:
    """The rule's own title and description are the question, not an anchor.
    Without them the labeller is guessing what they are being asked."""
    view = render(ENTRY, RULES)

    assert "Shell built from tool input" in view
    assert "A shell command is built from a string." in view


def test_the_view_hides_what_would_anchor_the_judgement() -> None:
    """Knowing the scanner rated this critical, or that it was already
    flagged with some confidence, anchors the answer. A ground truth anchored
    to the thing it is meant to judge is not a ground truth.
    """
    view = render(ENTRY, RULES)

    assert "critical" not in view
    assert "low" not in view


def test_the_view_hides_the_server_so_reputation_cannot_decide_it() -> None:
    """A well-known publisher's name makes a finding feel like a false
    positive, and an unknown one makes it feel real. Neither is evidence."""
    view = render(ENTRY, RULES)

    assert "acme" not in view
    assert "notes-server" not in view


def test_the_view_marks_which_line_was_flagged() -> None:
    """Twenty-five lines with nothing marked asks the labeller to guess the
    question. The flagged line is not reliably the middle one, because the
    window clamps near the top of a file.
    """
    view = render(ENTRY, RULES)
    marked = [line for line in view.splitlines() if line.startswith(">")]

    assert len(marked) == 1
    assert "exec(cmd)" in marked[0]


def test_an_entry_naming_a_rule_the_view_does_not_know_is_refused() -> None:
    """Rendering it without the claim would ask the labeller to judge an
    unstated question, and they would answer something."""
    with pytest.raises(KeyError, match="NO-SUCH-RULE"):
        render({**ENTRY, "rule_id": "NO-SUCH-RULE"}, RULES)


def test_the_tool_has_a_working_entry_point(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`python -m evals.golden.label` did nothing at all: the module had `run`
    and no argparse or `__main__` block, so the documented command printed
    nothing and recorded nothing. Found by running the command I had told
    somebody to run, which is the only way that class of defect surfaces.
    """
    from evals.golden.label import main

    path = tmp_path / "entries.jsonl"
    path.write_text(
        json.dumps(
            {
                "entry_id": "g-0001",
                "rule_id": "SHELL-EXEC-UNSAFE",
                "severity": "critical",
                "confidence": "low",
                "language": "typescript",
                "context": "const a = 1\nexec(cmd)",
                "flagged_offset": 1,
                "label": None,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("builtins.input", lambda _: "y")

    assert main(["--path", str(path)]) == 0
    assert json.loads(path.read_text())["label"] == "true_positive"


def test_a_missing_entries_file_says_to_draw_the_set_first(tmp_path: Path) -> None:
    """A stack trace here sends somebody to read the source of a tool they were
    told to run."""
    from evals.golden.label import main

    with pytest.raises(FileNotFoundError, match="draw the golden set"):
        main(["--path", str(tmp_path / "absent.jsonl")])


def test_a_label_records_who_made_it_and_why() -> None:
    """Ground truth that cannot be audited is ground truth that must be taken
    on trust, which is exactly what this project declines to ask of readers
    elsewhere. A reason makes a specific label disagreeable; a labeller makes
    the provenance of a mixed set recoverable.
    """
    updated = apply_label(
        ENTRIES, "g-0002", "false_positive", reason="header is dead code, nothing listens", by="model"
    )

    assert updated[1]["label"] == "false_positive"
    assert updated[1]["reason"] == "header is dead code, nothing listens"
    assert updated[1]["labelled_by"] == "model"


def test_a_human_label_supersedes_a_model_label_for_the_same_entry() -> None:
    """The set is meant to be labelled by a model and then validated by a
    person. If a human judgement did not win, validation would be decorative.
    """
    seeded = apply_label(ENTRIES, "g-0002", "true_positive", reason="reachable", by="model")

    validated = apply_label(seeded, "g-0002", "false_positive", reason="input is fixed", by="human")

    assert validated[1]["label"] == "false_positive"
    assert validated[1]["labelled_by"] == "human"


def test_a_label_without_a_reason_is_refused_for_a_model() -> None:
    """A model can produce a confident answer for free, so the cost of an
    unexamined one has to be reimposed deliberately. A human pressing a key is
    already making a judgement; a model writing a reason is the equivalent.
    """
    with pytest.raises(ValueError, match="reason"):
        apply_label(ENTRIES, "g-0002", "true_positive", by="model")


def test_an_unknown_labeller_is_refused() -> None:
    """Provenance with a free-text field is provenance nobody can filter on."""
    with pytest.raises(ValueError, match="labeller"):
        apply_label(ENTRIES, "g-0002", "true_positive", reason="x", by="committee")


def test_a_judgement_is_an_observation_under_a_condition() -> None:
    """The contribution is a comparison between two conditions, and the human
    validation is a second labeller on the same entries. Both need a judgement
    to carry who made it and what they were shown - a single `label` field can
    represent neither.
    """
    updated = observe(ENTRIES, "g-0002", "true_positive",
                      condition="window", reason="reachable", by="model")

    assert updated[1]["observations"]["window"]["label"] == "true_positive"
    assert updated[1]["observations"]["window"]["labelled_by"] == "model"


def test_the_same_entry_holds_both_conditions_independently() -> None:
    """The whole experiment is that these can differ. Storing one would make
    the effect unmeasurable."""
    entries = observe(ENTRIES, "g-0002", "unsure", condition="window",
                      reason="origin not visible", by="model")
    entries = observe(entries, "g-0002", "true_positive", condition="function",
                      reason="parameter reaches the shell unquoted", by="model")

    obs = entries[1]["observations"]
    assert obs["window"]["label"] == "unsure"
    assert obs["function"]["label"] == "true_positive"


def test_a_human_observation_sits_beside_a_model_one_rather_than_replacing_it() -> None:
    """Agreement between them is the figure to report, and overwriting would
    destroy the thing being measured."""
    entries = observe(ENTRIES, "g-0002", "true_positive", condition="function",
                      reason="x", by="model")
    entries = observe(entries, "g-0002", "false_positive", condition="function",
                      reason="y", by="human")

    obs = entries[1]["observations"]["function"]
    assert obs["label"] == "false_positive", "the human judgement is the ground truth"
    assert obs["superseded"]["label"] == "true_positive"
    assert obs["superseded"]["labelled_by"] == "model"


def test_an_unknown_condition_is_refused() -> None:
    with pytest.raises(ValueError, match="condition"):
        observe(ENTRIES, "g-0002", "true_positive", condition="vibes", reason="x", by="model")


def test_one_model_observation_is_published_as_it_stands() -> None:
    """With a single judgement there is nothing to weigh it against, so it is
    the best available answer."""
    entries = observe(ENTRIES, "g-0002", "unsure", condition="window", reason="x", by="model")

    assert published_label(entries[1]) == "unsure"


def test_conditions_that_agree_are_published() -> None:
    """Agreement across the contexts is the case where the annotation choice did
    not matter, which is most of them."""
    entries = observe(ENTRIES, "g-0002", "true_positive", condition="window", reason="x", by="model")
    entries = observe(entries, "g-0002", "true_positive", condition="function", reason="y", by="model")

    assert published_label(entries[1]) == "true_positive"


def test_conditions_that_disagree_publish_nothing() -> None:
    """This is the experiment feeding back into the code, and it replaces a
    preference the data refuted.

    The previous rule preferred the enclosing function over the window, on the
    stated grounds that the window was "the condition shown to be lossy". The
    experiment on 2026-09-26 found no such thing: no directional effect on either
    taint rule combined, and the two rules predicted to move disagreed with each
    other. What it did find is that the contexts reach different verdicts on
    roughly one finding in five.

    So there is no measured basis for preferring either, and picking one would
    publish an arbitrary verdict on exactly the findings where the answer is
    known to be unstable. A contested finding has no published label, and its
    share becomes a measured uncertainty the benchmark can report - which is
    worth more than a number that looks decisive and is not.
    """
    entries = observe(ENTRIES, "g-0002", "true_positive", condition="window", reason="x", by="model")
    entries = observe(entries, "g-0002", "false_positive", condition="function", reason="y", by="model")

    assert published_label(entries[1]) is None


def test_a_human_judgement_settles_a_contested_finding() -> None:
    """Ground truth is condition-independent: it is established from whatever it
    takes to answer, not from one of the two views under test. So it outranks any
    disagreement between them rather than joining it."""
    entries = observe(ENTRIES, "g-0002", "true_positive", condition="window", reason="x", by="model")
    entries = observe(entries, "g-0002", "false_positive", condition="function", reason="y", by="model")
    entries = apply_label(entries, "g-0002", "true_positive", reason="read the caller", by="human")

    assert published_label(entries[1]) == "true_positive"


def test_a_contested_finding_is_identifiable_not_merely_unlabelled() -> None:
    """An entry nobody judged and an entry the two contexts disagreed about both
    end up without a published label, and they are not the same thing: one needs
    a judgement, the other needs a human to break a tie. Reporting them together
    would hide the measured instability inside ordinary incompleteness."""
    entries = observe(ENTRIES, "g-0002", "true_positive", condition="window", reason="x", by="model")
    entries = observe(entries, "g-0002", "false_positive", condition="function", reason="y", by="model")

    assert is_contested(entries[1])
    assert not is_contested(entries[0])


def test_ground_truth_is_recorded_straight_to_the_file(tmp_path: Path) -> None:
    """A judgement made outside the interactive loop still has to be durable.

    The loop reads single keystrokes, which suits a person at a terminal and
    suits nothing else. Ground truth for the contested findings is established by
    reading code carefully rather than by pressing keys quickly, so it needs a way
    in that is not a TTY - and it must write immediately, for the same reason the
    loop does: work that is lost is work done twice.
    """
    path = tmp_path / "entries.jsonl"
    path.write_text(
        json.dumps({"entry_id": "g-0001", "rule_id": "SHELL-EXEC-UNSAFE", "label": None})
        + "\n"
        + json.dumps({"entry_id": "g-0002", "rule_id": "PATH-TRAVERSAL", "label": None})
        + "\n",
        encoding="utf-8",
    )

    record_truth(
        path, "g-0002", "true_positive", reason="the caller passes tool input", by="human"
    )

    written = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert written[1]["label"] == "true_positive"
    # `reason`, the field the schema already uses, not a second name for it.
    assert written[1]["reason"] == "the caller passes tool input"
    assert written[1]["labelled_by"] == "human"
    assert written[0]["label"] is None, "only the named entry is touched"


def test_ground_truth_requires_a_reason(tmp_path: Path) -> None:
    """The interactive loop lets a person press one key without explaining, on
    the grounds that they have already spent the attention. That does not hold
    here: these are the findings two contexts disagreed about, they are the ones a
    reader is most likely to challenge, and a label nobody can argue with
    individually is a label nobody can check.
    """
    path = tmp_path / "entries.jsonl"
    path.write_text(
        json.dumps({"entry_id": "g-0001", "rule_id": "SHELL-EXEC-UNSAFE", "label": None}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="reason"):
        record_truth(path, "g-0001", "true_positive", reason="   ", by="human")


def test_recording_ground_truth_refuses_an_unknown_entry(tmp_path: Path) -> None:
    """Doing nothing looks exactly like success, and the entry would simply be
    left unlabelled while the count said otherwise."""
    path = tmp_path / "entries.jsonl"
    path.write_text(
        json.dumps({"entry_id": "g-0001", "rule_id": "SHELL-EXEC-UNSAFE", "label": None}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(KeyError):
        record_truth(path, "g-9999", "true_positive", reason="x", by="human")


# --- provenance: who made a judgement is never assumed -----------------------

def test_recording_a_judgement_requires_naming_who_made_it() -> None:
    """The default was "human", and that default is how model labels became
    ground truth.

    On 2026-09-26 forty-eight golden-set labels were produced by Claude, a model,
    and twenty-nine of them were recorded as human because the helper that wrote
    them supplied "human" whenever no labeller was named. Nothing downstream could
    tell the difference, and a research result was reported as resting on human
    ground truth when it rested on one model grading another. A labeller that must
    be named cannot be mis-named by omission.
    """
    with pytest.raises(TypeError):
        apply_label(ENTRIES, "g-0002", "false_positive")  # type: ignore[call-arg]


def test_recording_ground_truth_requires_naming_who_made_it(tmp_path: Path) -> None:
    path = tmp_path / "entries.jsonl"
    path.write_text(
        json.dumps({"entry_id": "g-0001", "rule_id": "SHELL-EXEC-UNSAFE", "label": None}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(TypeError):
        record_truth(path, "g-0001", "true_positive", reason="x")  # type: ignore[call-arg]


def test_a_model_label_does_not_settle_a_contested_finding() -> None:
    """Ground truth outranks a disagreement between the two contexts only because
    it is independent of them. A label from another model is not independent: it
    is a third model reading the same code. So it is reported beside the others,
    and the finding stays contested until a person settles it.
    """
    entries = observe(ENTRIES, "g-0002", "true_positive", condition="window", reason="x", by="model")
    entries = observe(entries, "g-0002", "false_positive", condition="function", reason="y", by="model")
    entries = apply_label(entries, "g-0002", "false_positive", reason="read it", by="model")

    assert is_contested(entries[1])
    assert published_label(entries[1]) is None


def test_a_label_with_no_recorded_labeller_is_not_treated_as_human() -> None:
    """Fail closed on unknown provenance. Nineteen early labels were written before
    the labeller was recorded at all, and every one of them was a model's. Reading a
    missing field as "human" would repeat the original mistake on older data.
    """
    entries = observe(ENTRIES, "g-0002", "true_positive", condition="window", reason="x", by="model")
    entries = observe(entries, "g-0002", "false_positive", condition="function", reason="y", by="model")
    legacy = {**entries[1], "label": "false_positive"}
    legacy.pop("labelled_by", None)

    assert is_contested(legacy)
    assert published_label(legacy) is None
