"""Tests for pure GUI helpers."""

from __future__ import annotations

import unittest

from shellsuite.gui import query


class QueryTests(unittest.TestCase):
    def test_build_filter(self):
        self.assertEqual(query.build_filter("vector", "==", "post"), "vector == post")

    def test_build_filters_skips_blank_values(self):
        rows = [
            ("vector", "==", "post"),
            ("name", "contains", ""),
            ("mode", "!=", "plain"),
        ]
        self.assertEqual(
            query.build_filters(rows), ["vector == post", "mode != plain"]
        )

    def test_session_title(self):
        self.assertEqual(
            query.session_title("web1", "2026-01-01T00:00:00+00:00", "completed"),
            "web1 - 2026-01-01T00:00:00+00:00 - completed",
        )

    def test_default_direction(self):
        self.assertTrue(query.default_direction("started_at", ("started_at",)))
        self.assertFalse(query.default_direction("name", ("started_at",)))


if __name__ == "__main__":
    unittest.main()
