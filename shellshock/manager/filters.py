"""Shared filter parsing for registry and session listings."""

from __future__ import annotations

FILTER_OPS: tuple[str, ...] = ("==", "!=", "contains", ">", "<")


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
        raise FilterError(f"invalid --filter operator: {op!r} \n You must use one of the following: {list(FILTER_OPS)}")
    return attr, op, value


def matches(actual: str, op: str, value: str) -> bool:
    #contains
    if op == FILTER_OPS[2]:
        return value.lower() in actual.lower()
    #==
    if op == FILTER_OPS[0]:
        return actual == value
    #!=
    if op == FILTER_OPS[1]:
        return actual != value

    try:
        left = float(actual)
        right = float(value)
    except ValueError:
        left, right = actual, value
    
    #>
    if op == FILTER_OPS[3]:
        return left > right
    #<
    if op == FILTER_OPS[4]:
        return left < right
    
    raise FilterError("This operator is available but not implemented")
