"""Shared filter parsing for registry and session listings."""

from __future__ import annotations

FILTER_OPS: tuple[str, ...] = ("==", "!=", "contains")


class FilterError(ValueError):
    """Raised for an invalid filter expression."""


def parse(expression: str, fields) -> tuple[str, str, str]:
    """Parse ``"attr op value"`` and validate attr/op against ``fields``."""
    parts = expression.split(None, 2)
    if len(parts) != 3:
        raise FilterError(
            f"invalid --filter: {expression!r} (expected 'attr op value')"
        )
    attr, op, value = parts
    if attr not in fields:
        raise FilterError(f"invalid --filter attribute: {attr!r}")
    if op not in FILTER_OPS:
        raise FilterError(f"invalid --filter operator: {op!r} (use ==, !=, contains)")
    return attr, op, value


def matches(actual: str, op: str, value: str) -> bool:
    if op == "contains":
        return value.lower() in actual.lower()
    if op == "==":
        return actual == value
    return actual != value
