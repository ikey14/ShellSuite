"""End-to-end tests for `shellsuite shock create`."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest

from shellsuite import cli


class ShellshockCliTests(unittest.TestCase):
    def test_create_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "shell.php")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(
                    ["shock", "create", "--vector", "cookie",
                     "--mode", "plain", "--out", out]
                )
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.exists(out))

    def test_create_with_explicit_driver(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "shell.php")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(
                    ["shock", "create", "--vector", "cookie",
                     "--mode", "plain", "--driver", "system", "--out", out]
                )
            self.assertEqual(rc, 0)
            with open(out, encoding="utf-8") as fh:
                self.assertIn("system(", fh.read())

    def test_bad_vector_fails_cleanly(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf), self.assertRaises(SystemExit) as cm:
            cli.main(["shock", "create", "--vector", "bad", "--mode", "plain"])
        self.assertNotEqual(cm.exception.code, 0)
        self.assertNotIn("Traceback", buf.getvalue())

    def test_shock_is_discovered(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit) as cm:
            cli.main(["shock", "--help"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
