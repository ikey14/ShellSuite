"""Tests for the shared manager filter parsing and comparison."""

from __future__ import annotations

import unittest

from shellshock.manager import filters


class FilterTests(unittest.TestCase):
    def test_range_operators_are_supported(self):
        self.assertIn(">", filters.FILTER_OPS)
        self.assertIn("<", filters.FILTER_OPS)
        self.assertEqual(
            filters.parse("commands > 50", ("commands",)), ("commands", ">", "50")
        )
        self.assertEqual(
            filters.parse("duration < 30", ("duration",)), ("duration", "<", "30")
        )

    def test_numeric_comparisons(self):
        self.assertTrue(filters.matches("11", ">", "10"))
        self.assertFalse(filters.matches("9", ">", "10"))
        self.assertTrue(filters.matches("9", "<", "10"))
        self.assertFalse(filters.matches("11", "<", "10"))

    def test_date_equality_uses_utc_day(self):
        actual = "2026-01-02T13:45:00+00:00"
        self.assertTrue(filters.matches(actual, "==", "2026-01-02", date=True))
        self.assertFalse(filters.matches(actual, "==", "2026-01-02"))
        self.assertFalse(filters.matches(actual, "!=", "2026-01-02", date=True))
        self.assertTrue(filters.matches(actual, "!=", "2026-01-03", date=True))

    def test_date_ranges(self):
        actual = "2026-01-02T13:45:00+00:00"
        self.assertTrue(filters.matches(actual, ">", "2026-01-01", date=True))
        self.assertFalse(filters.matches(actual, ">", "2026-01-02", date=True))
        self.assertTrue(filters.matches(actual, "<", "2026-01-03", date=True))
        self.assertFalse(filters.matches(actual, "<", "2026-01-02", date=True))

    def test_missing_date_never_matches_range_or_equality(self):
        self.assertFalse(filters.matches("", ">", "2026-01-01", date=True))
        self.assertFalse(filters.matches("", "<", "2026-01-01", date=True))
        self.assertFalse(filters.matches("", "==", "2026-01-01", date=True))

    def test_contains_is_unchanged(self):
        self.assertTrue(filters.matches("Chrome", "contains", "rom"))
        self.assertFalse(filters.matches("Chrome", "contains", "fire"))


if __name__ == "__main__":
    unittest.main()
