"""The single place the Creator maps a vector to its PHP superglobal.

Used for the command value (generator) and the credential (auth), and reusable
for any future per-vector value. ``{var}`` is the PHP variable the value is
assigned to; ``{name}`` is the channel name (contract.PARAM_NAMES /
AUTH_PARAM_NAMES).
"""

from __future__ import annotations

from shellsuite.protocol import contract

_READERS: dict[str, str] = {
    "cookie": '{var} = isset($_COOKIE["{name}"]) ? $_COOKIE["{name}"] : "";',
    "header": (
        '$__ss_key = "HTTP_" . strtoupper(str_replace("-", "_", "{name}"));\n'
        '{var} = isset($_SERVER[$__ss_key]) ? $_SERVER[$__ss_key] : "";'
    ),
    "post": '{var} = isset($_POST["{name}"]) ? $_POST["{name}"] : "";',
}


def read(vector: str, var: str, name: str) -> str:
    """PHP that assigns the value carried on ``vector``'s channel to ``var``."""
    reader = _READERS.get(vector)
    if reader is None:
        raise ValueError(f"no reader for vector: {vector!r}")
    return reader.format(var=var, name=name)


def assert_conformance() -> None:
    """Raise if the readers don't exactly match contract.VECTORS."""
    if set(_READERS) != set(contract.VECTORS):
        raise ValueError("readers do not match contract.VECTORS")
