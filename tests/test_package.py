from importlib.metadata import version

import analyzer


def test_version_is_derived_from_installed_distribution_metadata() -> None:
    """The version is declared once, in pyproject.toml.

    Comparing the module attribute against the distribution metadata fails the
    moment someone reintroduces a hardcoded literal in __init__.py, which is
    the drift this guards against. It also proves the package is installed,
    since unreadable metadata raises rather than returning a wrong answer.
    """
    assert analyzer.__version__ == version("mcp-observatory") + "-deliberate-break"


_deliberate_type_break: int = "not an int"
