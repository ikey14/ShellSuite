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

    def _create(self, vector: str) -> str:
        """Generate a webshell via the CLI and return its source."""
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "shell.php")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(
                    ["shock", "create", "--vector", vector,
                     "--mode", "plain", "--out", out]
                )
            self.assertEqual(rc, 0)
            with open(out, encoding="utf-8") as fh:
                return fh.read()

    def test_create_header_reads_server_superglobal(self):
        self.assertIn("$_SERVER", self._create("header"))

    def test_create_post_reads_post_superglobal(self):
        self.assertIn('$_POST["shellshock"]', self._create("post"))

    def test_create_auth_writes_gated_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "shell.php")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(
                    ["shock", "create", "--vector", "cookie", "--mode", "auth",
                     "--secret", "hunter2", "--out", out]
                )
            self.assertEqual(rc, 0)
            with open(out, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("shellshock_auth", content)
            self.assertIn('hash("sha256"', content)

    def test_create_auth_without_secret_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "shell.php")
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                rc = cli.main(
                    ["shock", "create", "--vector", "cookie", "--mode", "auth",
                     "--out", out]
                )
            self.assertNotEqual(rc, 0)
            self.assertNotIn("Traceback", buf.getvalue())

    def test_create_encrypted_writes_decrypting_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "shell.php")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.main(
                    ["shock", "create", "--vector", "cookie", "--mode", "encrypted",
                     "--secret", "hunter2", "--out", out]
                )
            self.assertEqual(rc, 0)
            with open(out, encoding="utf-8") as fh:
                content = fh.read()
            self.assertIn("__ss_decrypt", content)
            self.assertIn("__ss_encrypt", content)
            self.assertIn("SSENC1.", content)

    def test_create_encrypted_without_secret_fails_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "shell.php")
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                rc = cli.main(
                    ["shock", "create", "--vector", "cookie", "--mode", "encrypted",
                     "--out", out]
                )
            self.assertNotEqual(rc, 0)
            self.assertNotIn("Traceback", buf.getvalue())

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
