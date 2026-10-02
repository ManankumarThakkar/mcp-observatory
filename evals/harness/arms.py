"""Which judge a run uses."""

from analyzer.triage.base import Adjudicator
from analyzer.triage.jev import JevAdjudicator, post_json

ARMS = ("jev", "frontier")


def adjudicator_for(arm: str) -> Adjudicator:
    """Build the named judge.

    The frontier client is imported only when asked for: it lives in the
    optional `triage` extra, and the scanner must run without it.
    """
    if arm == "jev":
        return JevAdjudicator(post_json)
    if arm == "frontier":
        try:
            import anthropic
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "the frontier arm needs the triage extra: pip install -e '.[triage]'"
            ) from exc
        from analyzer.triage.frontier import FrontierAdjudicator

        return FrontierAdjudicator(anthropic.Anthropic())
    raise ValueError(f"no such arm {arm!r}; choose from {', '.join(ARMS)}")
