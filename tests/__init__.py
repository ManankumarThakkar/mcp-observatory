"""Makes `tests` a package so shared fixtures can be imported by name.

Without this, `from tests.conftest import ...` resolves under pytest's own path
handling and fails under mypy - a difference that only shows up in CI, which is
the worst place to find it.
"""
