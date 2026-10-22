"""Tests for the URL transport encoding."""

from __future__ import annotations

import unittest

from shellsuite.protocol import encoding


class EncodingTests(unittest.TestCase):
    def test_round_trip(self):
        for value in [
            "id",
            "cat /etc/passwd",
            'echo "a;b&c"',
            "100% +",
            "a+b",
            "ñonga",
        ]:
            self.assertEqual(encoding.decode(encoding.encode(value)), value, value)

    def test_encodes_delimiters(self):
        encoded = encoding.encode("a b;c&d=e/f+g")
        for ch in " ;&=+/":
            self.assertNotIn(ch, encoded)

    def test_leaves_unreserved_characters(self):
        self.assertEqual(encoding.encode("AZaz09-_.~"), "AZaz09-_.~")


if __name__ == "__main__":
    unittest.main()
