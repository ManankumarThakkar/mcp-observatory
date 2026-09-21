from pathlib import Path

from analyzer.rules.base import FileContext
from analyzer.rules.unicode_conceal import UnicodeConcealRule

TAG_CHAR = "\U000E0041"  # TAG LATIN CAPITAL LETTER A
BIDI_OVERRIDE = "\u202e"  # RIGHT-TO-LEFT OVERRIDE
BIDI_ISOLATE = "\u2066"  # LEFT-TO-RIGHT ISOLATE
ZERO_WIDTH_SPACE = "\u200b"
BOM = "\ufeff"


def _ctx(source: str) -> FileContext:
    return FileContext(
        server_id="owner/repo",
        commit_sha="b" * 40,
        relative_path="src/server.py",
        source=source,
    )


def test_tag_block_character_is_flagged_with_its_line_number() -> None:
    """A TAG character is invisible to a human reading the file.

    It carries a letter that the model reading the tool description will act
    on, which is the entire attack: the reviewer and the model see different
    text.
    """
    source = f'name = "ok"\ndescription = "read files{TAG_CHAR}"\n'

    findings = UnicodeConcealRule().analyze(_ctx(source))

    assert len(findings) == 1
    assert findings[0].rule_id == "UNICODE-CONCEAL"
    assert findings[0].severity == "critical"
    assert findings[0].confidence == "high"
    assert findings[0].location.line == 2
    assert findings[0].location.file == "src/server.py"


def test_bidirectional_override_is_flagged_with_high_confidence() -> None:
    """The Trojan Source attack.

    An override changes the order source *renders* in without changing the
    order it *parses* in, so a reviewer reads one program and the machine
    reads another. There is no innocent reason for one in a tool description.
    """
    findings = UnicodeConcealRule().analyze(_ctx(f'desc = "safe{BIDI_OVERRIDE}"\n'))

    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert "bidi-override" in findings[0].evidence


def test_bidi_isolate_is_flagged_but_less_confidently() -> None:
    """Isolates do appear in legitimate internationalised text.

    Reported rather than suppressed, because concealment is still possible,
    but at lower confidence so the published precision figure is not dragged
    down by characters that often have an innocent explanation.
    """
    findings = UnicodeConcealRule().analyze(_ctx(f'desc = "x{BIDI_ISOLATE}y"\n'))

    assert len(findings) == 1
    assert findings[0].severity == "critical", "impact is unchanged"
    assert findings[0].confidence == "medium", "likelihood is not"


def test_zero_width_space_is_flagged_less_confidently() -> None:
    findings = UnicodeConcealRule().analyze(_ctx(f'desc = "a{ZERO_WIDTH_SPACE}b"\n'))

    assert len(findings) == 1
    assert findings[0].confidence == "medium"


def test_emoji_joiner_sequences_are_not_findings() -> None:
    """U+200D is structural in emoji, not concealment.

    Including it made one family emoji produce two critical findings, which
    would have fired on ordinary READMEs across the whole corpus.
    """
    family = "\U0001f468\u200d\U0001f469\u200d\U0001f467"

    assert UnicodeConcealRule().analyze(_ctx(f'description = "Family {family}"\n')) == []


def test_persian_zero_width_non_joiner_is_not_a_finding() -> None:
    """U+200C is required to spell words correctly in Persian and Indic scripts."""
    assert UnicodeConcealRule().analyze(_ctx('label = "م\u200cی"\n')) == []


def test_ordinary_source_produces_no_findings() -> None:
    source = 'name = "read_file"\ndescription = "Reads a file from disk."\n'

    assert UnicodeConcealRule().analyze(_ctx(source)) == []


def test_a_byte_order_mark_at_the_start_of_a_file_is_not_a_finding() -> None:
    """A BOM is an encoding artefact, not concealment.

    The scanner reads utf-8-sig so one should not normally reach here, but a
    rule that is only correct when its caller behaves is a rule waiting for a
    second caller. Handled here as well, so the decoder's behaviour is defence
    in depth rather than load-bearing.
    """
    source = f'{BOM}description = "Reads a file."\n'

    assert UnicodeConcealRule().analyze(_ctx(source)) == []


def test_a_byte_order_mark_elsewhere_in_the_file_is_still_a_finding() -> None:
    """Only position zero is an encoding artefact. Anywhere else is anomalous."""
    source = f'description = "Reads{BOM} a file."\n'

    findings = UnicodeConcealRule().analyze(_ctx(source))

    assert len(findings) == 1
    assert "zero-width-nbsp" in findings[0].evidence


def test_the_rule_is_wired_into_all_rules() -> None:
    """A rule that exists but is not collected never runs.

    This is the check the old registry design could not offer: there, a
    forgotten import disabled a detection silently. Here it is one assertion.
    """
    from analyzer.rules import ALL_RULES

    assert any(rule.rule_id == "UNICODE-CONCEAL" for rule in ALL_RULES)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_the_vulnerable_fixture_is_flagged_and_the_clean_one_is_not() -> None:
    """The fixtures are the rule's contact with something resembling reality.

    The vulnerable one hides TAG characters spelling an instruction inside an
    otherwise ordinary description, so a reviewer reading the file sees
    nothing wrong while a model reading the metadata sees the hidden letters.
    """
    vulnerable = (FIXTURES / "vulnerable" / "unicode_conceal_server.py").read_text("utf-8")
    clean = (FIXTURES / "clean" / "plain_server.py").read_text("utf-8")

    assert UnicodeConcealRule().analyze(_ctx(vulnerable))
    assert UnicodeConcealRule().analyze(_ctx(clean)) == []
