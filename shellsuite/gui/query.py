"""Pure, Tk-free helpers shared by the GUI views."""

from __future__ import annotations


def build_filter(field: str, operator: str, value: str) -> str:
    """Build the CLI filter expression ``"field operator value"``."""
    return f"{field.strip()} {operator.strip()} {value.strip()}"


def build_filters(rows) -> list[str]:
    """Turn ``(field, operator, value)`` rows into CLI expressions, skipping blanks."""
    expressions = []
    for field, operator, value in rows:
        if value is None or str(value).strip() == "":
            continue
        expressions.append(build_filter(field, operator, str(value)))
    return expressions


def session_title(shell: str, started_at: str, status: str) -> str:
    """Card title for a session."""
    return f"{shell} - {started_at} - {status}"


def default_direction(order: str, date_fields) -> bool:
    """True for descending, used for date fields by default."""
    return order in date_fields
