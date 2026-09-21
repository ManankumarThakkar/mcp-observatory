"""Static analysis of published MCP servers.

The version is declared once, in pyproject.toml, and read back from the
installed distribution metadata so the two can never disagree.
"""

from importlib.metadata import version

__version__ = version("mcp-observatory")
