"""Unit tests for the Python side of payload encryption."""

from __future__ import annotations

import unittest

from shellsuite import crypto
from shellsuite.protocol import contract


class CryptoTests(unittest.TestCase):
    def test_round_trip(self):
        payload = crypto.encrypt("id", "hunter2")
        self.assertEqual(crypto.decrypt(payload, "hunter2"), "id")

    def test_empty_payload_round_trip(self):
        payload = crypto.encrypt("", "hunter2")
        self.assertEqual(crypto.decrypt(payload, "hunter2"), "")

    def test_prefix_and_urlsafe_alphabet(self):
        payload = crypto.encrypt("id", "hunter2")
        self.assertTrue(payload.startswith(contract.ENCRYPTED_PREFIX))
        body = payload[len(contract.ENCRYPTED_PREFIX):]
        for ch in "+/=":
            self.assertNotIn(ch, body)

    def test_wrong_password_does_not_recover_plaintext(self):
        payload = crypto.encrypt("id", "hunter2")
        self.assertNotEqual(crypto.decrypt(payload, "wrong"), "id")

    def test_rejects_non_enveloped_payload(self):
        with self.assertRaises(ValueError):
            crypto.decrypt("id", "hunter2")

    def test_fixed_nonce_is_deterministic(self):
        a = crypto.encrypt("id", "hunter2", nonce=b"12345678")
        b = crypto.encrypt("id", "hunter2", nonce=b"12345678")
        self.assertEqual(a, b)

    def test_nonce_changes_ciphertext(self):
        a = crypto.encrypt("id", "hunter2", nonce=b"12345678")
        b = crypto.encrypt("id", "hunter2", nonce=b"1234567X")
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    unittest.main()
