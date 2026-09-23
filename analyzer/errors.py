"""Failures the caller can fix, told apart from failures we caused."""


class InputError(ValueError):
    """Bad input the caller supplied: a flag, a file, a value.

    Exists because the boundary has to report one of these as a sentence and
    must not report anything else that way. A plain ValueError raised inside
    this codebase means an invariant the code is supposed to maintain has been
    violated, and several of those are load-bearing: Finding refuses an
    unknown severity because an unrecognised one maps to the lowest SARIF
    level, so a critical finding would publish as a note; the disclosure gate
    refuses a naive datetime because the ninety-day window would be computed
    against an unknown offset; the history refuses a placeholder commit sha.

    Each of those guards is worth having only if it is loud. Catching
    ValueError at the boundary made all of them print the same tidy line as a
    mistyped flag, and a defect that exits with a one-line message is a defect
    nobody goes looking for.

    Subclasses ValueError rather than Exception so callers and tests that
    already expect a ValueError from these paths keep working, and so the
    narrowing is the boundary's choice rather than a change to every raiser.
    """
