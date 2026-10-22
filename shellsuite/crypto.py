"""Symmetric payload encryption for encrypted-mode webshells.

Scheme: XOR with a keystream derived from HMAC-SHA256(password, nonce || counter).
Envelope: ``<prefix><base64url(nonce || ciphertext)>`` (base64url, no padding).
The same scheme is implemented in PHP (shellshock/creator/crypto.py); both sides
take prefix, nonce length and scheme from the contract.

Only the payloads exchanged with a shell are encrypted; the shell source itself
is not. The password is provided at runtime and never stored.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from .protocol import contract


def _keystream(password: bytes, nonce: bytes, length: int) -> bytes:
    """HMAC-SHA256 counter-mode keystream, ``length`` bytes long."""
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        stream += hmac.new(
            password, nonce + str(counter).encode("ascii"), hashlib.sha256
        ).digest()
        counter += 1
    return bytes(stream[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(text: str, password: str, nonce: bytes | None = None) -> str:
    """Encrypt ``text`` into the contract envelope."""
    data = text.encode("utf-8")
    if nonce is None:
        nonce = os.urandom(contract.NONCE_BYTES)
    ciphertext = _xor(data, _keystream(password.encode("utf-8"), nonce, len(data)))
    encoded = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii").rstrip("=")
    return contract.ENCRYPTED_PREFIX + encoded


def decrypt(payload: str, password: str) -> str:
    """Decrypt an envelope produced by this module or by the PHP shell."""
    if not payload.startswith(contract.ENCRYPTED_PREFIX):
        raise ValueError("not an encrypted payload")
    body = payload[len(contract.ENCRYPTED_PREFIX):]
    raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
    if len(raw) < contract.NONCE_BYTES:
        raise ValueError("encrypted payload too short")
    nonce = raw[: contract.NONCE_BYTES]
    ciphertext = raw[contract.NONCE_BYTES:]
    return _xor(
        ciphertext, _keystream(password.encode("utf-8"), nonce, len(ciphertext))
    ).decode("utf-8", "replace")
