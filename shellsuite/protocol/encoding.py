"""Transport encoding for command payloads and credentials.

Both are percent-encoded on the wire (RFC 3986; "unreserved" characters are left
as-is). The generated webshell applies ``urldecode()`` before using a value, so
arbitrary commands, delimiters and non-ASCII passwords survive every vector.
"""

from __future__ import annotations

from urllib.parse import quote, unquote


def encode(value: str) -> str:
    """Percent-encode ``value`` for transport (UTF-8; only unreserved chars pass)."""
    return quote(value, safe="")


def decode(value: str) -> str:
    """Inverse of :func:`encode` (used by tests and for symmetry)."""
    return unquote(value)
