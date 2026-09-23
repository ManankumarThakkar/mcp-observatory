"""Detect characters that hide text from a human reviewer but not from a model."""

from analyzer.models import Confidence, Finding, Location
from analyzer.rules.base import FileContext

# Codepoints that can hide text from a reader, with how conclusive each one is.
#
# Severity is critical throughout: the impact is identical if the concealment
# is real. Confidence carries the likelihood instead, because these characters
# are not equally damning. A TAG character or a bidi override has no innocent
# explanation in source. An isolate or a zero-width space sometimes does, and
# reporting those at the same confidence would drag down a precision figure
# this project publishes.
#
# U+200C and U+200D are deliberately absent. Both are load-bearing in emoji
# sequences and in Persian and Indic scripts; including them made a single
# family emoji produce two critical findings.
SUSPECT_RANGES: tuple[tuple[int, int, str, Confidence], ...] = (
    (0xE0000, 0xE007F, "unicode-tag-block", "high"),
    (0x202A, 0x202E, "bidi-override", "high"),
    (0x2066, 0x2069, "bidi-isolate", "medium"),
    (0x200B, 0x200B, "zero-width-space", "medium"),
    (0xFEFF, 0xFEFF, "zero-width-nbsp", "medium"),
)


def _classify(char: str) -> tuple[str, Confidence] | None:
    codepoint = ord(char)
    for low, high, label, confidence in SUSPECT_RANGES:
        if low <= codepoint <= high:
            return label, confidence
    return None


class UnicodeConcealRule:
    rule_id = "UNICODE-CONCEAL"
    title = "Characters hidden from human review"
    description = (
        "Source contains codepoints that are invisible to a human reader "
        "but are read normally by a language model: tag characters, "
        "bidirectional overrides and zero-width marks. Text hidden this way "
        "can instruct an assistant to do something the developer never sees "
        "and never approved."
    )

    def analyze(self, ctx: FileContext) -> list[Finding]:
        findings: list[Finding] = []

        # A U+FEFF at position zero describes how the file was encoded rather
        # than hiding anything in it. Dropped here as well as by the scanner's
        # decoder, so this rule stays correct no matter how a caller reads the
        # file. The same character anywhere else is genuinely anomalous and is
        # still reported.
        source = ctx.source.removeprefix("\ufeff")

        # split("\n") rather than splitlines(). splitlines() also breaks on
        # U+2028, U+2029, U+0085 and several C0 controls, none of which git, an
        # editor or a reviewer counts as a line. A file prefixed with invisible
        # separators could therefore choose the line number published against
        # it, so a reviewer opening the file found nothing there and read a
        # true finding as a false positive. It also shifted finding_id, which
        # includes the line, giving the same issue a new identity each run.
        #
        # Those separators now remain visible to the loop below as ordinary
        # characters on their line, rather than being consumed as structure.
        for line_number, line in enumerate(source.split("\n"), start=1):
            for char in line:
                classified = _classify(char)
                if classified is None:
                    continue
                label, confidence = classified
                findings.append(
                    Finding(
                        server_id=ctx.server_id,
                        commit_sha=ctx.commit_sha,
                        rule_id=self.rule_id,
                        severity="critical",
                        confidence=confidence,
                        location=Location(file=ctx.relative_path, line=line_number),
                        evidence=f"{label} U+{ord(char):04X} at line {line_number}",
                    )
                )
                break  # one finding per line is enough to flag it

        return findings
