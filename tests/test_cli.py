"""Smoke tests for the top-level shellsuite dispatcher.

Run with:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import contextlib
import io
import unittest

from shellsuite import __version__, cli


class DispatcherTests(unittest.TestCase):
    def test_version_flag(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
            cli.main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn(__version__, buf.getvalue())

    def test_help_flag(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
            cli.main(["--help"])
        self.assertEqual(cm.exception.code, 0)
        self.assertIn("shellsuite", buf.getvalue())

    def test_no_module_prints_help(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.main([])
        self.assertEqual(rc, 0)
        self.assertIn("usage", buf.getvalue().lower())

    def test_unknown_module_fails_cleanly(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf), self.assertRaises(SystemExit) as cm:
            cli.main(["doesnotexist", "info"])
        self.assertNotEqual(cm.exception.code, 0)
        self.assertNotIn("Traceback", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
